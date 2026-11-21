from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="dns_doh",
    category="dns",
    description="Authoritative DNS record lookup via Google's public DNS-over-HTTPS resolver.",
    consumes="domain",
    produces=("ip", "mx", "ns", "txt"),
    passive=True,
    source_url="https://dns.google/resolve",
)

_RECORD_TYPES = {
    "A": "ip",
    "AAAA": "ip",
    "MX": "mx",
    "NS": "ns",
    "TXT": "txt",
}


def run(target: str, ctx: RunContext) -> list[Finding]:
    findings: list[Finding] = []
    for record_type, finding_type in _RECORD_TYPES.items():
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
