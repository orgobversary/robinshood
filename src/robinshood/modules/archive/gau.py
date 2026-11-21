from __future__ import annotations

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="gau",
    category="archive",
    description=(
        "Fetch known URLs for a domain from the Wayback Machine, AlienVault OTX, "
        "Common Crawl, and URLScan in one pass (local CLI)."
    ),
    consumes="domain",
    produces=("archived_url",),
    requires_bin=("gau",),
    passive=True,
    source_url="https://github.com/lc/gau",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    domain = safe_target(target)
    # No -subs: stays scoped to this domain, matching wayback_cdx's
    # {target}/* scoping rather than exploding into every subdomain gau knows.
    stdout = ctx.exec(["gau", domain], timeout=600.0)
    seen: set[str] = set()
    findings: list[Finding] = []
    for line in stdout.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        findings.append(
            Finding(type="archived_url", value=url, module=MODULE.name, target=domain, source_url=MODULE.source_url)
        )
    return findings
