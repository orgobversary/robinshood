from __future__ import annotations

import pathlib
import tempfile

from robinshood.core.shell import safe_target
from robinshood.core.types import Finding, ModuleSpec, RunContext

# Added at explicit user request (github.com/s0md3v/Photon) despite being an
# active crawl of the target's own site — AGENTS.md's scope boundary permits
# this class of tool only when the user explicitly asks for it.
MODULE = ModuleSpec(
    name="photon",
    category="crawl",
    description=(
        "Crawl a domain's own website (multiple pages, bounded depth) to collect emails and "
        "URLs (local CLI via git-clone + shim — see INSTALL.md). Sends many requests directly "
        "to the target."
    ),
    consumes="domain",
    produces=("email", "url"),
    requires_bin=("photon",),
    passive=False,
    source_url="https://github.com/s0md3v/Photon",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    domain = safe_target(target)
    seed_url = f"https://{domain}"
    findings: list[Finding] = []

    with tempfile.TemporaryDirectory() as workdir:
        # --level/--threads pinned explicitly (not left to Photon's own
        # defaults) for a bounded runtime; --output keeps result files inside
        # the tempdir instead of cwd, same reasoning as sherlock.
        ctx.exec(
            ["photon", "-u", seed_url, "--output", workdir, "--level", "2", "--threads", "2"],
            timeout=900.0,
            cwd=workdir,
        )
        out_dir = pathlib.Path(workdir)

        # Photon has no stdout protocol — results live in output files.
        # intel.txt lines are "<page-url>:EMAIL:user@example.com" (Photon's
        # own writer joins url, intel_name, and match with ":" — confirmed
        # against a live run; a naive split on the first ":" breaks because
        # the page URL itself contains "://"). Search for the ":EMAIL:"
        # marker instead of assuming position.
        intel_path = out_dir / "intel.txt"
        if intel_path.exists():
            for line in intel_path.read_text(encoding="utf-8", errors="replace").splitlines():
                _, sep, value = line.strip().partition(":EMAIL:")
                if sep and "@" in value:
                    findings.append(
                        Finding(
                            type="email",
                            value=value.strip(),
                            module=MODULE.name,
                            target=domain,
                            source_url=MODULE.source_url,
                            confidence="Unverified",
                        )
                    )

        # internal.txt: in-scope URLs discovered while crawling.
        internal_path = out_dir / "internal.txt"
        if internal_path.exists():
            seen: set[str] = set()
            for line in internal_path.read_text(encoding="utf-8", errors="replace").splitlines():
                url = line.strip()
                if not url or url in seen:
                    continue
                seen.add(url)
                findings.append(
                    Finding(
                        type="url",
                        value=url,
                        module=MODULE.name,
                        target=domain,
                        source_url=MODULE.source_url,
                        confidence="Unverified",
                    )
                )

    return findings
