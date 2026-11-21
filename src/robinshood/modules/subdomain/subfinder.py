from __future__ import annotations

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="subfinder",
    category="subdomain",
    description="Passive subdomain enumeration from 30+ sources (local CLI).",
    consumes="domain",
    produces=("domain",),
    requires_bin=("subfinder",),
    passive=True,
    source_url="https://github.com/projectdiscovery/subfinder",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    domain = safe_target(target)

    # No -active flag: subfinder stays on passive sources and never resolves
    # against the target's own nameservers.
    stdout = ctx.exec(["subfinder", "-d", domain, "-silent"], timeout=600.0)

    seen: set[str] = set()
    findings: list[Finding] = []
    for line in stdout.splitlines():
        name = line.strip().lower()
        if not name or name == domain or name in seen:
            continue
        seen.add(name)
        findings.append(
            Finding(
                type="domain",
                value=name,
                module=MODULE.name,
                target=domain,
                source_url=MODULE.source_url,
            )
        )
    return findings
