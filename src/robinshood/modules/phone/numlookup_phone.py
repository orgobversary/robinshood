from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="numlookup_phone",
    category="phone",
    description="Phone number validation, carrier, and line type via NumLookupAPI.",
    consumes="phone",
    produces=("carrier", "line_type", "geo"),
    requires_key=("NUMLOOKUP_API_KEY",),
    passive=True,
    source_url="https://api.numlookupapi.com/v1/validate/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    api_key = ctx.env.get("NUMLOOKUP_API_KEY")
    if not api_key:
        raise RuntimeError(
            "NUMLOOKUP_API_KEY not set — get a free key (100 lookups/month) at "
            "https://numlookupapi.com/"
        )

    # The API takes the number bare (no leading '+') per its own docs example.
    number = target.lstrip("+")
    url = f"https://api.numlookupapi.com/v1/validate/{number}"
    resp = ctx.http.get(url, params={"apikey": api_key})
    resp.raise_for_status()
    data = resp.json()

    # An invalid/unrecognized number is absent data about the world, not a
    # failed lookup — same "empty result, not an error" rule as a 404.
    if not data.get("valid"):
        return []

    findings: list[Finding] = []
    carrier = data.get("carrier")
    if carrier:
        findings.append(
            Finding(type="carrier", value=carrier, module=MODULE.name, target=target, source_url=url)
        )

    line_type = data.get("line_type")
    if line_type and line_type != "N/A":
        findings.append(
            Finding(type="line_type", value=line_type, module=MODULE.name, target=target, source_url=url)
        )

    location = data.get("location")
    country = data.get("country_name")
    geo = ", ".join(part for part in (location, country) if part)
    if geo:
        findings.append(
            Finding(
                type="geo", value=geo, module=MODULE.name, target=target, source_url=url,
                raw={"country_code": data.get("country_code")},
            )
        )
    return findings
