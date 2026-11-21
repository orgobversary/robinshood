from __future__ import annotations

import json

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleSpec, RunContext

# Wraps ProjectDiscovery's Go binary `httpx` (a local CLI tool resolved via
# shutil.which) — unrelated to the Python `httpx` package imported in
# core/types.py for ctx.http. No code collision, only a naming one; hence
# httpx_probe as the module name, not httpx.
MODULE = ModuleSpec(
    name="httpx_probe",
    category="infra",
    description=(
        "Send one live HTTP probe to a domain via ProjectDiscovery's httpx CLI, confirming "
        "reachability, status code, and title. Sends real traffic to the target's own "
        "infrastructure, unlike every other module here."
    ),
    consumes="domain",
    produces=("url",),
    requires_bin=("httpx",),
    passive=False,
    source_url="https://github.com/projectdiscovery/httpx",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    domain = safe_target(target)
    stdout = ctx.exec(
        ["httpx", "-u", domain, "-json", "-silent", "-status-code", "-title", "-tech-detect"],
        timeout=30.0,
    )
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        url = record.get("url") or record.get("input")
        if not url:
            continue
        findings.append(
            Finding(
                type="url",
                value=url,
                module=MODULE.name,
                target=domain,
                source_url=MODULE.source_url,
                raw=record,
            )
        )
    return findings
