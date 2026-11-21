from __future__ import annotations

import re

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="amass",
    category="subdomain",
    description="OWASP Amass passive subdomain enumeration across dozens of OSINT sources (local CLI).",
    consumes="domain",
    produces=("domain",),
    requires_bin=("amass",),
    passive=True,
    source_url="https://github.com/owasp-amass/amass",
)

# Defends against a banner/summary line slipping past -silent on some amass
# versions (behavior has drifted across releases — verify against the
# installed binary before relying on it).
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def run(target: str, ctx: RunContext) -> list[Finding]:
    domain = safe_target(target)
    # -passive keeps amass on OSINT/API sources only — no DNS resolution
    # against the target's own nameservers, mirroring subfinder's deliberate
    # omission of -active.
    stdout = ctx.exec(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=600.0)
    seen: set[str] = set()
    findings: list[Finding] = []
    for line in stdout.splitlines():
        name = line.strip().lower()
        if not name or name == domain or name in seen or not _HOSTNAME_RE.match(name):
            continue
        seen.add(name)
        findings.append(
            Finding(type="domain", value=name, module=MODULE.name, target=domain, source_url=MODULE.source_url)
        )
    return findings
