from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="rdap_domain",
    category="whois",
    description="RDAP registration lookup for a domain — registrar, nameservers, key dates.",
    consumes="domain",
    produces=("registrar", "nameserver"),
    passive=True,
    source_url="https://rdap.org/domain/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = f"https://rdap.org/domain/{target}"
    resp = ctx.http.get(url)
    resp.raise_for_status()
    data = resp.json()
    findings: list[Finding] = []

    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            handle = entity.get("handle", entity.get("vcardArray", ""))
            findings.append(
                Finding(
                    type="registrar",
                    value=str(handle) or "unknown registrar",
                    module=MODULE.name,
                    target=target,
                    source_url=url,
                    raw=entity,
                )
            )

    for ns in data.get("nameservers", []):
        name = ns.get("ldhName")
        if name:
            findings.append(
                Finding(
                    type="nameserver",
                    value=name,
                    module=MODULE.name,
                    target=target,
                    source_url=url,
                    raw=ns,
                )
            )

    return findings
