from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="wayback_cdx",
    category="archive",
    description="Query the Internet Archive's CDX index for historical snapshots of a domain.",
    consumes="domain",
    produces=("archived_url",),
    passive=True,
    source_url="http://web.archive.org/cdx/search/cdx",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{target}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "digest",
        "limit": "50",
    }
    resp = ctx.http.get(url, params=params)
    resp.raise_for_status()
    rows = resp.json()
    if not rows:
        return []

    header, *body = rows
    findings: list[Finding] = []
    for row in body:
        record = dict(zip(header, row))
        findings.append(
            Finding(
                type="archived_url",
                value=record.get("original", ""),
                module=MODULE.name,
                target=target,
                source_url=url,
                raw=record,
            )
        )
    return findings
