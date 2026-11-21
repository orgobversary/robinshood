from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="shodan_internetdb",
    category="infra",
    description="Free, no-auth Shodan InternetDB lookup — open ports, CPEs, known vulnerabilities for an IP.",
    consumes="ip",
    produces=("port", "cpe", "vuln"),
    passive=True,
    source_url="https://internetdb.shodan.io/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = f"https://internetdb.shodan.io/{target}"
    resp = ctx.http.get(url)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    data = resp.json()

    findings: list[Finding] = []
    for port in data.get("ports", []):
        findings.append(
            Finding(type="port", value=str(port), module=MODULE.name, target=target, source_url=url)
        )
    for cpe in data.get("cpes", []):
        findings.append(
            Finding(type="cpe", value=cpe, module=MODULE.name, target=target, source_url=url)
        )
    for vuln in data.get("vulns", []):
        findings.append(
            Finding(type="vuln", value=vuln, module=MODULE.name, target=target, source_url=url)
        )
    return findings
