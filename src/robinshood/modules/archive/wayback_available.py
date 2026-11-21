from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="wayback_available",
    category="archive",
    description="Check whether a specific URL has an archived Wayback Machine snapshot.",
    consumes="url",
    produces=("archived_url",),
    passive=True,
    source_url="http://archive.org/wayback/available",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = "http://archive.org/wayback/available"
    resp = ctx.http.get(url, params={"url": target})
    resp.raise_for_status()
    snapshot = resp.json().get("archived_snapshots", {}).get("closest")
    if not snapshot or not snapshot.get("available"):
        return []
    return [
        Finding(
            type="archived_url",
            value=snapshot["url"],
            module=MODULE.name,
            target=target,
            source_url=f"{url}?url={target}",
            raw={"timestamp": snapshot.get("timestamp"), "status": snapshot.get("status")},
        )
    ]
