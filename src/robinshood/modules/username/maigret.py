from __future__ import annotations

import json
import tempfile
from pathlib import Path

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="maigret",
    category="username",
    description="Search for a username across 2500+ sites (local CLI) — broader coverage than sherlock.",
    consumes="username",
    produces=("profile",),
    requires_bin=("maigret",),
    passive=True,
    source_url="https://github.com/soxoj/maigret",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    username = safe_target(target)

    # maigret writes reports to a folder rather than stdout; run it inside a
    # temp dir so it never litters the user's cwd. --json ndjson gives one
    # JSON object per line per confirmed hit (verified against maigret 0.6.5's
    # source: report.py:generate_json_report / maigret.py's report_filepath_tpl).
    with tempfile.TemporaryDirectory() as workdir:
        ctx.exec(
            [
                "maigret", username,
                "--json", "ndjson",
                "--folderoutput", workdir,
                "--timeout", "10",
                "--no-progressbar",
            ],
            timeout=600.0,
            cwd=workdir,
        )
        # maigret sanitizes the username into the filename (e.g. "/" -> "_");
        # globbing avoids re-implementing that sanitization here.
        reports = list(Path(workdir).glob("report_*_ndjson.json"))
        lines = reports[0].read_text(encoding="utf-8").splitlines() if reports else []

    findings: list[Finding] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        url = row.get("url_user")
        if not url:
            continue
        findings.append(
            Finding(
                type="profile",
                value=url,
                module=MODULE.name,
                target=username,
                source_url=MODULE.source_url,
                raw={"site": row.get("sitename")},
                confidence="Unverified",
            )
        )
    return findings
