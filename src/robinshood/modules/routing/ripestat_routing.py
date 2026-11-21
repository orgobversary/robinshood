from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="ripestat_routing",
    category="routing",
    description="Announcing ASN and covering BGP prefix for an IP, via RIPEstat.",
    consumes="ip",
    produces=("asn", "prefix"),
    passive=True,
    source_url="https://stat.ripe.net/data/network-info/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    net_url = "https://stat.ripe.net/data/network-info/data.json"
    resp = ctx.http.get(net_url, params={"resource": target})
    resp.raise_for_status()
    data = resp.json().get("data", {})

    findings: list[Finding] = []
    prefix = data.get("prefix")
    if prefix:
        findings.append(
            Finding(
                type="prefix", value=prefix, module=MODULE.name, target=target,
                source_url=f"{net_url}?resource={target}",
            )
        )

    for asn in data.get("asns") or []:
        raw = {}
        # A second, best-effort call for the ASN's holder name — dns_doh already
        # sets the precedent of several calls per module for a fuller picture.
        overview_url = "https://stat.ripe.net/data/as-overview/data.json"
        try:
            overview = ctx.http.get(overview_url, params={"resource": f"AS{asn}"})
            if overview.status_code == 200:
                raw["holder"] = overview.json().get("data", {}).get("holder")
        except Exception:  # noqa: BLE001 - the enrichment call is optional, never fatal
            pass
        findings.append(
            Finding(
                type="asn", value=str(asn), module=MODULE.name, target=target,
                source_url=f"{net_url}?resource={target}", raw=raw or None,
            )
        )
    return findings
