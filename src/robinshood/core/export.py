from __future__ import annotations

import itertools
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from robinshood.core.case import Case, list_cases, slugify
from robinshood.core.detect import detect_target_type
from robinshood.core.types import utc_now

GENERATOR = "robinshood"
DEFAULT_LIMIT = 50

# Case slugs come from directory names on disk, so validate before using one to
# build a write path — a hand-made directory must not be able to escape the vault.
_SAFE_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class ExportError(Exception):
    """Raised for conditions the user needs to act on, not bugs."""


def default_limit(env: dict | None = None) -> int:
    """Findings inlined per type, from $ROBINSHOOD_EXPORT_LIMIT when set."""
    env = env if env is not None else os.environ
    raw = env.get("ROBINSHOOD_EXPORT_LIMIT")
    if raw is None or not str(raw).strip():
        return DEFAULT_LIMIT
    try:
        value = int(raw)
    except ValueError:
        raise ExportError(
            f"ROBINSHOOD_EXPORT_LIMIT must be an integer, got {raw!r}"
        ) from None
    if value < 0:
        raise ExportError("ROBINSHOOD_EXPORT_LIMIT cannot be negative (use 0 for unlimited)")
    return value


def human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


@dataclass
class ExportPreview:
    """What a single case would write, computed without touching the vault."""

    slug: str
    finding_count: int
    shown_count: int
    note_bytes: int
    exists: bool
    blocked_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.blocked_reason is None

    @property
    def status(self) -> str:
        if self.blocked_reason:
            return self.blocked_reason
        return "overwrite" if self.exists else "new"


@dataclass
class FindingGroup:
    type: str
    values: list[tuple[str, list[str], str]] = field(default_factory=list)
    # (value, modules that produced it, confidence)


def _yaml_str(value: str) -> str:
    """Quotes a scalar for YAML frontmatter. Targets are user-supplied, so never
    interpolate one bare into a document Obsidian will parse."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _fmt_duration(ms: float) -> str:
    if ms >= 1000:
        return f"{ms / 1000:.1f}s"
    return f"{ms:.0f}ms"


def _dedupe_findings(findings: list[dict]) -> list[FindingGroup]:
    """Findings are append-only, so re-running a module repeats values. Collapse
    to unique (type, value), remembering every module that reported it."""
    groups: dict[str, FindingGroup] = {}
    seen: dict[tuple[str, str], int] = {}
    for row in findings:
        ftype = row.get("type", "unknown")
        value = row.get("value", "")
        module = row.get("module", "")
        group = groups.setdefault(ftype, FindingGroup(type=ftype))
        key = (ftype, value)
        if key in seen:
            modules = group.values[seen[key]][1]
            if module not in modules:
                modules.append(module)
            continue
        seen[key] = len(group.values)
        group.values.append((value, [module], row.get("confidence", "Probable")))
    return list(groups.values())


def _render_value(value: str, own_slug: str, known_slugs: set[str]) -> str:
    """A finding whose value is itself an exported case becomes a wiki link, so
    the Obsidian graph gets real edges. Everything else stays inline code."""
    slug = slugify(value)
    if slug != own_slug and slug in known_slugs:
        return f"[[{slug}|{value}]]"
    return f"`{value}`"


def render_note(
    slug: str,
    findings: list[dict],
    evidence: list[dict],
    limit: int = DEFAULT_LIMIT,
    known_slugs: set[str] | None = None,
    labels: list[dict] | None = None,
    module_info: dict[str, tuple[str, bool]] | None = None,
    contacts: list[dict] | None = None,
) -> str:
    """module_info maps module name -> (category, passive), typically built once by
    the caller from the registry (`{e.spec.name: (e.spec.category, e.spec.passive)
    for e in load_registry()}`). A module name absent from it (e.g. stale evidence
    from a since-removed module) degrades to category "unknown" and counts as
    non-passive in the passive_only rollup, so a module robinshood can no longer
    verify never silently claims a case is passive-only.

    `contacts` is the case's egress receipts (Case.load_contacts()) — every
    outbound point of contact robinshood's own runs actually made. Optional and
    defaulting to none, so existing callers/tests built before egress logging
    existed keep working unchanged."""
    return _render(
        slug,
        findings,
        _dedupe_findings(findings),
        evidence,
        limit=limit,
        known_slugs=known_slugs,
        labels=labels,
        module_info=module_info,
        contacts=contacts,
    )


def _render(
    slug: str,
    findings: list[dict],
    groups: list[FindingGroup],
    evidence: list[dict],
    limit: int = DEFAULT_LIMIT,
    known_slugs: set[str] | None = None,
    labels: list[dict] | None = None,
    module_info: dict[str, tuple[str, bool]] | None = None,
    contacts: list[dict] | None = None,
) -> str:
    """render_note's body, taking already-deduped groups. Split out so preview
    and export can share one _dedupe_findings pass over a large case rather
    than each paying for their own."""
    known_slugs = known_slugs or set()
    module_info = module_info or {}

    target = ""
    # chain, not (*evidence, *findings): the splat materialized a combined tuple
    # of every row in the case just to read the first target off the front.
    for row in itertools.chain(evidence, findings):
        if row.get("target"):
            target = row["target"]
            break
    if not target:
        target = slug

    unique_count = sum(len(g.values) for g in groups)
    modules = sorted({row.get("module", "") for row in evidence if row.get("module")})
    timestamps = sorted(row["started_at"] for row in evidence if row.get("started_at"))
    target_type = detect_target_type(target) or "unknown"

    # Single pass over confidence values, shared by the has_unverified frontmatter
    # field below and the warning callout in the findings section.
    unverified_count = sum(1 for g in groups for _, _, confidence in g.values if confidence == "Unverified")
    has_unverified = unverified_count > 0

    categories = sorted({module_info.get(m, ("unknown", False))[0] for m in modules})
    finding_types = sorted(g.type for g in groups)
    passive_only = all(module_info.get(m, ("unknown", False))[1] for m in modules) if modules else True

    label_set = sorted({row["label"] for row in (labels or [])})

    out: list[str] = []

    # ── frontmatter ──────────────────────────────────────────────
    out.append("---")
    out.append(f"target: {_yaml_str(target)}")
    out.append(f"target_type: {target_type}")
    if timestamps:
        out.append(f"first_seen: {timestamps[0]}")
        out.append(f"last_run: {timestamps[-1]}")
    out.append(f"modules: [{', '.join(modules)}]" if modules else "modules: []")
    out.append(f"finding_count: {unique_count}")
    out.append(f"run_count: {len(evidence)}")
    out.append(f"tags: [recon/{target_type}]")
    out.append(f"labels: [{', '.join(label_set)}]" if label_set else "labels: []")
    out.append(f"categories: [{', '.join(categories)}]" if categories else "categories: []")
    out.append(f"finding_types: [{', '.join(finding_types)}]" if finding_types else "finding_types: []")
    out.append(f"passive_only: {'true' if passive_only else 'false'}")
    out.append(f"has_unverified: {'true' if has_unverified else 'false'}")
    out.append("record_type: case")
    # Marks the note as a regenerable view. export refuses to overwrite a file
    # without this, so a hand-written note is never silently destroyed.
    out.append(f"generator: {GENERATOR}")
    out.append("---")
    out.append("")
    out.append(f"# {target}")
    out.append("")
    if has_unverified:
        out.append(
            f"> [!warning] {unverified_count:,} finding(s) below are Unverified — "
            f"confirm manually before treating them as fact."
        )
        out.append("")

    # ── findings ─────────────────────────────────────────────────
    if not groups:
        out.append("No findings recorded.")
        out.append("")
    for group in groups:
        shown = group.values if limit <= 0 else group.values[:limit]
        out.append(f"## {group.type} ({len(group.values)})")
        out.append("")
        for value, mods, confidence in shown:
            rendered = _render_value(value, slug, known_slugs)
            line = f"- {rendered} — {', '.join(mods)}"
            if confidence != "Probable":
                line += f" · *{confidence}*"
            out.append(line)
        hidden = len(group.values) - len(shown)
        if hidden > 0:
            out.append("")
            out.append(
                f"> [!note]- {hidden:,} more not shown"
                f"\n> Raw values are in `cases/{slug}/findings.jsonl`. "
                f"Re-export with `--limit 0` to inline them all."
            )
        out.append("")

    # ── runs ─────────────────────────────────────────────────────
    out.append("## Runs")
    out.append("")
    if evidence:
        out.append("| module | ok | findings | duration | started |")
        out.append("|---|---|---|---|---|")
        for row in evidence:
            ok = "yes" if row.get("ok") else "no"
            out.append(
                f"| `{row.get('module', '')}` "
                f"| {ok} "
                f"| {row.get('finding_count', 0):,} "
                f"| {_fmt_duration(float(row.get('duration_ms') or 0))} "
                f"| {row.get('started_at', '')} |"
            )
        out.append("")
        failures = [r for r in evidence if not r.get("ok")]
        if failures:
            out.append("### Failed runs")
            out.append("")
            for row in failures:
                out.append(f"- `{row.get('module', '')}` — {row.get('error', 'unknown error')}")
            out.append("")
    else:
        out.append("No runs recorded.")
        out.append("")

    # ── outbound contacts ────────────────────────────────────────
    # A receipt of what robinshood's own runs actually put on the wire — from
    # the outside looking in, not what was learned about the target. Rendered
    # in file order (contacts.jsonl is append-only), same as the Runs table
    # above: no reordering needed for determinism, since the source file
    # itself is fixed at export time.
    out.append("## Outbound contacts")
    out.append("")
    contacts = contacts or []
    if contacts:
        out.append(
            "> [!info] What robinshood's own traffic looked like from the outside — "
            "destination, proxy, user-agent, and Tor-rotation state for every actual "
            "attempt. CLI-wrapper modules (subfinder, sherlock, ...) can only be logged "
            "as 'invoked' — their own network calls happen inside their own process, "
            "invisible to robinshood."
        )
        out.append("")
        out.append("| module | kind | destination | proxy | tor | status |")
        out.append("|---|---|---|---|---|---|")
        for row in contacts:
            proxy = row.get("proxy") or "direct"
            tor = "yes" if row.get("tor_rotated") else "no"
            status = row.get("status", "")
            if row.get("error"):
                status = f"{status} — {row['error']}"
            out.append(
                f"| `{row.get('module', '')}` "
                f"| {row.get('kind', '')} "
                f"| `{row.get('destination', '')}` "
                f"| {proxy} "
                f"| {tor} "
                f"| {status} |"
            )
        out.append("")
    else:
        out.append("No outbound contacts recorded.")
        out.append("")

    # Always linked, whether or not the companion exists — an unresolved link is
    # harmless in Obsidian, and making it conditional would tie the rendered
    # bytes to vault state and break determinism.
    out.append("## Analysis")
    out.append("")
    out.append(f"Your notes for this case: [[{notes_slug(slug)}]]")
    out.append("")

    out.append("---")
    out.append(
        f"*Generated by robinshood from `cases/{slug}/`. "
        f"This note is a derived view — edits are lost on re-export. "
        f"Write anything you want to keep in [[{notes_slug(slug)}]].*"
    )
    out.append("")

    return "\n".join(out)


def notes_slug(slug: str) -> str:
    """Companion note for analyst writing. Kept separate from the generated note
    because that one is overwritten on every export."""
    return f"{slug}-notes"


def attach_note(
    vault_dir: Path,
    slug: str,
    title: str,
    body: str,
    timestamp: str | None = None,
) -> Path:
    """Creates or appends to the case's companion note. robinshood never
    overwrites this file — analyst writing is not regenerable."""
    if not _SAFE_SLUG.match(slug):
        raise ExportError(f"refusing to write a note for unsafe case name: {slug!r}")
    title = title.strip()
    body = body.strip()
    if not title and not body:
        raise ExportError("a note needs a title or a body")
    title = title or "Note"
    stamp = timestamp or utc_now()

    vault_dir.mkdir(parents=True, exist_ok=True)
    path = vault_dir / f"{notes_slug(slug)}.md"

    if path.exists():
        # Append. Overwriting would destroy earlier analysis.
        existing = path.read_text(encoding="utf-8")
        addition = f"\n## {title}\n*{stamp}*\n\n{body}\n"
        if not existing.endswith("\n"):
            addition = "\n" + addition
        path.write_text(existing + addition, encoding="utf-8")
        return path

    header = [
        "---",
        f"case: {slug}",
        "type: analysis",
        "tags: [recon/analysis]",
        f"created: {stamp}",
        "---",
        "",
        f"# Notes — {slug}",
        "",
        f"Case: [[{slug}]]",
        "",
        f"## {title}",
        f"*{stamp}*",
        "",
        body,
        "",
    ]
    path.write_text("\n".join(header), encoding="utf-8")
    return path


def is_generated(path: Path) -> bool:
    """True only if the file's frontmatter carries our generator marker."""
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return False
    if not head.startswith("---"):
        return False
    _, _, rest = head.partition("---")
    frontmatter, sep, _ = rest.partition("\n---")
    if not sep:
        return False
    return f"generator: {GENERATOR}" in frontmatter


def _prepare(case: Case) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    if not _SAFE_SLUG.match(case.slug):
        raise ExportError(f"refusing to export case with unsafe name: {case.slug!r}")
    findings = case.load_findings()
    evidence = case.load_evidence()
    if not findings and not evidence:
        raise ExportError(f"case {case.slug!r} has no findings and no runs — nothing to export")
    return findings, evidence, case.load_labels(), case.load_contacts()


def preview_case(
    case: Case,
    vault_dir: Path,
    limit: int = DEFAULT_LIMIT,
    force: bool = False,
    known_slugs: set[str] | None = None,
    module_info: dict[str, tuple[str, bool]] | None = None,
) -> ExportPreview:
    """Exactly what export_case would write, without writing it. Renders through
    the same function, so the previewed byte count cannot drift from reality."""
    try:
        findings, evidence, labels, contacts = _prepare(case)
    except ExportError as exc:
        return ExportPreview(
            slug=case.slug,
            finding_count=0,
            shown_count=0,
            note_bytes=0,
            exists=False,
            blocked_reason=str(exc).split(" — ")[-1] if " — " in str(exc) else "cannot export",
        )

    # One dedupe pass, shared by the render and the counts below — render_note
    # would otherwise do its own, doubling the work on a 40k-finding case.
    groups = _dedupe_findings(findings)
    note = _render(
        case.slug, findings, groups, evidence, limit=limit, known_slugs=known_slugs,
        labels=labels, module_info=module_info, contacts=contacts,
    )
    total = sum(len(g.values) for g in groups)
    shown = sum(len(g.values) if limit <= 0 else min(len(g.values), limit) for g in groups)

    note_path = vault_dir / f"{case.slug}.md"
    exists = note_path.exists()
    blocked = None
    if exists and not is_generated(note_path) and not force:
        blocked = "not ours — skipped"

    return ExportPreview(
        slug=case.slug,
        finding_count=total,
        shown_count=shown,
        note_bytes=len(note.encode("utf-8")),
        exists=exists,
        blocked_reason=blocked,
    )


def preview_export(
    cases_root: Path,
    vault_dir: Path,
    slugs: list[str],
    limit: int = DEFAULT_LIMIT,
    force: bool = False,
    module_info: dict[str, tuple[str, bool]] | None = None,
) -> list[ExportPreview]:
    known = set(list_cases(cases_root))
    return [
        preview_case(
            Case(cases_root, slug), vault_dir, limit=limit, force=force,
            known_slugs=known, module_info=module_info,
        )
        for slug in slugs
    ]


def export_case(
    case: Case,
    vault_dir: Path,
    limit: int = DEFAULT_LIMIT,
    force: bool = False,
    known_slugs: set[str] | None = None,
    module_info: dict[str, tuple[str, bool]] | None = None,
) -> Path:
    findings, evidence, labels, contacts = _prepare(case)

    vault_dir.mkdir(parents=True, exist_ok=True)
    note_path = vault_dir / f"{case.slug}.md"

    if note_path.exists() and not is_generated(note_path) and not force:
        raise ExportError(
            f"{note_path} exists and was not written by robinshood — "
            f"refusing to overwrite. Move it aside, or pass --force."
        )

    note_path.write_text(
        render_note(
            case.slug, findings, evidence, limit=limit, known_slugs=known_slugs,
            labels=labels, module_info=module_info, contacts=contacts,
        ),
        encoding="utf-8",
    )
    return note_path
