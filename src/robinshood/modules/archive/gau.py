from __future__ import annotations

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleOption, ModuleSpec, RunContext

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
    options=(
        ModuleOption(
            name="include_subdomains",
            description="Include URLs belonging to subdomains of the target.",
            kind="bool",
            default=False,
        ),
        ModuleOption(
            name="providers",
            description="Comma-separated upstream archives to query; unset uses gau's defaults.",
            kind="choice_list",
            choices=("wayback", "commoncrawl", "otx", "urlscan"),
        ),
        ModuleOption(
            name="threads",
            description="Number of gau workers; unset uses gau's default.",
            kind="int",
            minimum=1,
            maximum=50,
        ),
    ),
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    domain = safe_target(target)
    argv = ["gau"]
    if ctx.option("include_subdomains", False):
        argv.append("--subs")
    providers = ctx.option("providers")
    if providers:
        argv.extend(["--providers", ",".join(providers)])
    threads = ctx.option("threads")
    if threads is not None:
        argv.extend(["--threads", str(threads)])
    argv.append(domain)
    stdout = ctx.exec(argv, timeout=600.0)
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
