from __future__ import annotations

import re

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="ipinfo_geo",
    category="geolocation",
    description="IP geolocation, ASN, and hosting metadata from ipinfo.io's free tier.",
    consumes="ip",
    produces=("geo", "asn"),
    passive=True,
    source_url="https://ipinfo.io/",
)

_ASN_RE = re.compile(r"^(AS\d+)")


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = f"https://ipinfo.io/{target}/json"
    resp = ctx.http.get(url)
    resp.raise_for_status()
    data = resp.json()

    findings: list[Finding] = []
    geo_parts = [data.get(k) for k in ("city", "region", "country") if data.get(k)]
    if geo_parts:
        findings.append(
            Finding(
                type="geo",
                value=", ".join(geo_parts),
                module=MODULE.name,
                target=target,
                source_url=url,
                raw={k: data.get(k) for k in ("loc", "postal", "timezone")},
            )
        )

    org = data.get("org", "")
    asn_match = _ASN_RE.match(org)
    if asn_match:
        findings.append(
            Finding(
                type="asn",
                value=asn_match.group(1),
                module=MODULE.name,
                target=target,
                source_url=url,
                raw={"org": org},
            )
        )

    return findings
