from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="rdap_ip",
    category="whois",
    description="RDAP lookup for an IP address — netname, ASN, country, abuse contact.",
    consumes="ip",
    produces=("asn", "netname"),
    passive=True,
    source_url="https://rdap.org/ip/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = f"https://rdap.org/ip/{target}"
    resp = ctx.http.get(url)
    resp.raise_for_status()
    data = resp.json()
    findings: list[Finding] = []

    netname = data.get("name")
    if netname:
        findings.append(
            Finding(
                type="netname",
                value=netname,
                module=MODULE.name,
                target=target,
                source_url=url,
                raw={k: data.get(k) for k in ("handle", "startAddress", "endAddress", "country")},
            )
        )

    for asn in data.get("arin_originas0_originautnums", []):
        findings.append(
            Finding(
                type="asn",
                value=str(asn),
                module=MODULE.name,
                target=target,
                source_url=url,
            )
        )

    return findings
