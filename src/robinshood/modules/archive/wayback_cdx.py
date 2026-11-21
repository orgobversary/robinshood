from __future__ import annotations

from robinshood.core.types import Finding, ModuleOption, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="wayback_cdx",
    category="archive",
    description="Query the Internet Archive's CDX index for historical snapshots of a domain.",
    consumes="domain",
    produces=("archived_url",),
    passive=True,
    source_url="http://web.archive.org/cdx/search/cdx",
    options=(
        ModuleOption(
            name="limit",
            description="Maximum number of CDX rows to request.",
            kind="int",
            default=50,
            minimum=1,
            maximum=10000,
        ),
        ModuleOption(
            name="collapse",
            description="CDX field used to collapse duplicate snapshots; 'none' disables collapse.",
            kind="choice",
            default="digest",
            choices=("digest", "urlkey", "timestamp", "none"),
        ),
    ),
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{target}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "limit": str(ctx.option("limit", 50)),
    }
    collapse = ctx.option("collapse", "digest")
    if collapse != "none":
        params["collapse"] = collapse
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
