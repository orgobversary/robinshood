from __future__ import annotations

import re

from robinshood.core.shell import safe_target
from robinshood.core.options import ModuleOptionError
from robinshood.core.types import Finding, ModuleOption, ModuleSpec, RunContext


_RECORD_TYPES = (
    "A",
    "AAAA",
    "ANY",
    "AXFR",
    "CAA",
    "CNAME",
    "DNSKEY",
    "MX",
    "NS",
    "SOA",
    "SRV",
    "TXT",
)


def validate_options(options: dict) -> None:
    server = options.get("server")
    if options.get("record_type") == "AXFR" and not server:
        raise ModuleOptionError(
            "dig_dns AXFR requires server=AUTHORITATIVE_NAMESERVER"
        )
    if options.get("record_type") == "AXFR" and options.get("transport") not in {
        "auto",
        "tcp",
    }:
        raise ModuleOptionError("dig_dns AXFR transport must be auto or tcp")
    if server:
        try:
            safe_target(server)
        except ValueError as exc:
            raise ModuleOptionError(f"invalid dig_dns server: {exc}") from exc

_FINDING_TYPES = {
    "A": "ip",
    "AAAA": "ip",
    "CAA": "caa",
    "CNAME": "domain",
    "DNSKEY": "dnskey",
    "MX": "mx",
    "NS": "ns",
    "SOA": "soa",
    "SRV": "srv",
    "TXT": "txt",
}


MODULE = ModuleSpec(
    name="dig_dns",
    category="dns",
    description=(
        "Query DNS directly with BIND dig, including explicitly authorized zone-transfer requests."
    ),
    consumes="domain",
    produces=("ip", "caa", "domain", "dnskey", "mx", "ns", "soa", "srv", "txt", "dns_record"),
    requires_bin=("dig",),
    # Direct queries and especially AXFR contact a DNS server selected by the
    # operator. Keep the whole module behind the active-module confirmation.
    passive=False,
    source_url="https://bind9.readthedocs.io/en/stable/manpages.html#dig-dns-lookup-utility",
    options=(
        ModuleOption(
            name="record_type",
            description="DNS query type. AXFR requests a full zone transfer and always uses TCP.",
            kind="choice",
            default="A",
            choices=_RECORD_TYPES,
        ),
        ModuleOption(
            name="server",
            description="Authoritative resolver hostname or IP; unset uses resolv.conf.",
            kind="str",
        ),
        ModuleOption(
            name="transport",
            description="DNS transport; auto uses dig defaults, while tcp/tls/https force one.",
            kind="choice",
            default="auto",
            choices=("auto", "tcp", "tls", "https"),
        ),
        ModuleOption(
            name="dnssec",
            description="Request DNSSEC records by setting dig's DNSSEC OK bit.",
            kind="bool",
            default=False,
        ),
        ModuleOption(
            name="timeout",
            description="Per-query dig timeout in seconds.",
            kind="int",
            default=5,
            minimum=1,
            maximum=60,
        ),
        ModuleOption(
            name="tries",
            description="Number of query attempts.",
            kind="int",
            default=3,
            minimum=1,
            maximum=5,
        ),
    ),
)


def _finding_value(record_type: str, rdata: str) -> str:
    if record_type in {"CNAME", "NS"}:
        return rdata.rstrip(".")
    if record_type == "TXT":
        return rdata.strip('"')
    return rdata


def run(target: str, ctx: RunContext) -> list[Finding]:
    domain = safe_target(target)
    record_type = ctx.option("record_type", "A")
    timeout = ctx.option("timeout", 5)
    tries = ctx.option("tries", 3)
    server = ctx.option("server")
    if record_type == "AXFR" and not server:
        raise RuntimeError(
            "AXFR requires --option server=AUTHORITATIVE_NAMESERVER"
        )

    # -r ignores ~/.digrc so an evidence record maps to a predictable argv.
    argv = [
        "dig",
        "-r",
        "+noall",
        "+answer",
        "+comments",
        f"+timeout={timeout}",
        f"+tries={tries}",
    ]
    if server:
        server = safe_target(server)
        argv.append(f"@{server}")
    argv.extend([domain, record_type])
    transport = ctx.option("transport", "auto")
    if transport != "auto" and not (record_type == "AXFR" and transport == "tcp"):
        argv.append(f"+{transport}")
    if ctx.option("dnssec", False):
        argv.append("+dnssec")

    command_timeout = max(30.0, float(timeout * tries + 10))
    stdout = ctx.exec(argv, timeout=command_timeout)
    status_match = re.search(r"\bstatus:\s*([A-Z0-9]+)", stdout)
    if status_match and status_match.group(1) != "NOERROR":
        raise RuntimeError(f"dig returned DNS status {status_match.group(1)}")
    if record_type == "AXFR" and "Transfer failed." in stdout:
        raise RuntimeError("dig zone transfer failed")
    source = server or "system-resolver"
    scheme = "dns" if transport == "auto" else f"dns+{transport}"
    source_url = f"{scheme}://{source}/{domain}?type={record_type}"

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        fields = line.split(None, 4)
        if len(fields) != 5:
            continue
        owner, ttl, record_class, answer_type, rdata = fields
        answer_type = answer_type.upper()
        finding_type = _FINDING_TYPES.get(answer_type, "dns_record")
        value = _finding_value(answer_type, rdata)
        key = (finding_type, value)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                type=finding_type,
                value=value,
                module=MODULE.name,
                target=domain,
                source_url=source_url,
                raw={
                    "owner": owner.rstrip("."),
                    "ttl": ttl,
                    "class": record_class,
                    "record_type": answer_type,
                    "rdata": rdata,
                    "server": source,
                },
            )
        )
    if record_type == "AXFR" and not findings:
        raise RuntimeError("dig AXFR returned no zone records")
    return findings
