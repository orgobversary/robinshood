from __future__ import annotations

import tempfile

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="sherlock",
    category="username",
    description="Search for a username across 400+ social media platforms and forums (local CLI).",
    consumes="username",
    produces=("profile",),
    requires_bin=("sherlock",),
    passive=True,
    source_url="https://github.com/sherlock-project/sherlock",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    username = safe_target(target)

    # sherlock writes a results .txt into its working directory; run it inside a
    # temp dir so it never litters the user's cwd, regardless of version.
    with tempfile.TemporaryDirectory() as workdir:
        # --no-color guarantees parseable output. sherlock already drops color
        # when stdout is not a TTY, but relying on that would fail silently
        # (mis-parsed lines) if it ever forced color; an unknown flag fails loudly.
        stdout = ctx.exec(
            ["sherlock", username, "--timeout", "10", "--print-found", "--no-color"],
            timeout=600.0,
            cwd=workdir,
        )

    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("[+]"):
            continue
        body = line[3:].strip()
        site, sep, url = body.partition(": ")
        if not sep or not url.startswith("http"):
            continue
        findings.append(
            Finding(
                type="profile",
                value=url.strip(),
                module=MODULE.name,
                target=username,
                source_url=MODULE.source_url,
                raw={"site": site.strip()},
                # sherlock is known to produce false positives on some platforms;
                # each hit needs a human to confirm the profile is really this user.
                confidence="Unverified",
            )
        )
    return findings
