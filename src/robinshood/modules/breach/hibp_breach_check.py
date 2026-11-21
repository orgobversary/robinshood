from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="hibp_breach_check",
    category="breach",
    description="Check whether an email appears in any known breach via Have I Been Pwned.",
    consumes="email",
    produces=("breach_bool",),
    requires_key=("HIBP_API_KEY",),
    passive=True,
    source_url="https://haveibeenpwned.com/api/v3/breachedaccount/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    api_key = ctx.env.get("HIBP_API_KEY")
    if not api_key:
        raise RuntimeError(
            "HIBP_API_KEY not set — get a free key at https://haveibeenpwned.com/API/Key"
        )

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
    resp = ctx.http.get(url, headers={"hibp-api-key": api_key})

    if resp.status_code == 404:
        return [
            Finding(
                type="breach_bool",
                value="not found in any known breach",
                module=MODULE.name,
                target=target,
                source_url=url,
            )
        ]

    resp.raise_for_status()
    breaches = resp.json()
    names = [b.get("Name", "unknown") for b in breaches]
    return [
        Finding(
            type="breach_bool",
            value=f"found in {len(names)} breach(es)",
            module=MODULE.name,
            target=target,
            source_url=url,
            raw={"breaches": names},
        )
    ]
