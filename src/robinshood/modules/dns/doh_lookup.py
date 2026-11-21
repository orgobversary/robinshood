from __future__ import annotations

from robinshood.core.types import Finding, ModuleOption, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="dns_doh",
    category="dns",
    description="DNS record lookup via Google's public DNS-over-HTTPS resolver.",
    consumes="domain",
    produces=("ip", "mx", "ns", "txt", "domain", "caa", "soa", "srv"),
    passive=True,
    source_url="https://dns.google/resolve",
    options=(
        ModuleOption(
            name="record_types",
            description="Comma-separated DNS record types to request through DNS-over-HTTPS.",
            kind="choice_list",
            default=("A", "AAAA", "MX", "NS", "TXT"),
            choices=("A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT"),
        ),
    ),
)

_RECORD_TYPES = {
    "A": "ip",
    "AAAA": "ip",
    "MX": "mx",
    "NS": "ns",
    "TXT": "txt",
    "CAA": "caa",
    "CNAME": "domain",
    "SOA": "soa",
    "SRV": "srv",
}


def run(target: str, ctx: RunContext) -> list[Finding]:
    findings: list[Finding] = []
    record_types = ctx.option("record_types", ("A", "AAAA", "MX", "NS", "TXT"))
    for record_type in record_types:
        finding_type = _RECORD_TYPES[record_type]
        resp = ctx.http.get(
            "https://dns.google/resolve",
            params={"name": target, "type": record_type},
        )
        resp.raise_for_status()
        data = resp.json()
        for answer in data.get("Answer", []):
            raw_value = answer.get("data", "")
            value = raw_value.strip('"') if record_type == "TXT" else raw_value
            findings.append(
                Finding(
                    type=finding_type,
                    value=value,
                    module=MODULE.name,
                    target=target,
                    source_url=f"https://dns.google/resolve?name={target}&type={record_type}",
                    raw=answer,
                )
            )
    return findings
