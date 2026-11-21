from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="ripestat_abuse",
    category="routing",
    description="Registered abuse-contact address for the network block an IP belongs to.",
    consumes="ip",
    produces=("abuse_contact",),
    passive=True,
    source_url="https://stat.ripe.net/data/abuse-contact-finder/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = "https://stat.ripe.net/data/abuse-contact-finder/data.json"
    resp = ctx.http.get(url, params={"resource": target})
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return [
        Finding(
            type="abuse_contact",
            value=contact,
            module=MODULE.name,
            target=target,
            source_url=f"{url}?resource={target}",
        )
        for contact in data.get("abuse_contacts") or []
    ]
