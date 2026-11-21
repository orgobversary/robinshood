from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from robinshood.core.egress import ContactEvent, contact_asdict
from robinshood.core.types import Finding, ModuleResult, utc_now

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    slug = _SLUG_RE.sub("-", text.strip().lower()).strip("-")
    return slug or "case"


def list_cases(root: Path) -> list[str]:
    """Slugs of every case on disk, in stable order."""
    if not root.is_dir():
        return []
    return sorted(
        p.name
        for p in root.iterdir()
        if p.is_dir() and ((p / "findings.jsonl").exists() or (p / "evidence.jsonl").exists())
    )


def _read_jsonl(path: Path) -> list[dict]:
    """Iterates the open file rather than read_text().splitlines(), so a large
    findings.jsonl never holds the raw text, a list of lines, and a list of
    dicts in memory at the same time."""
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class Case:
    """One investigation. Findings/evidence are append-only JSONL files —
    plain text, greppable, deletable, and fully rebuildable from re-runs."""

    def __init__(self, root: Path, slug: str):
        self.slug = slug
        self.dir = root / slug
        self.dir.mkdir(parents=True, exist_ok=True)
        self.findings_path = self.dir / "findings.jsonl"
        self.evidence_path = self.dir / "evidence.jsonl"
        self.labels_path = self.dir / "labels.jsonl"
        self.contacts_path = self.dir / "contacts.jsonl"

    @classmethod
    def open(cls, root: Path, name: str) -> "Case":
        return cls(root, slugify(name))

    def record_result(self, result: ModuleResult) -> None:
        self._append_evidence(result)
        self._append_findings(result.findings)
        self._append_contacts(result.contacts)

    def _append_findings(self, findings: list[Finding]) -> None:
        """One open() per module run, not per finding. A subdomain sweep emits
        tens of thousands of findings; opening the file for each one turned a
        single append into 25k open/write/close cycles."""
        if not findings:
            return
        with self.findings_path.open("a", encoding="utf-8") as fh:
            fh.writelines(
                json.dumps(asdict(f), ensure_ascii=False) + "\n" for f in findings
            )

    def _append_contacts(self, contacts: list[ContactEvent]) -> None:
        """The egress receipts for one module run — a fourth append-only
        JSONL alongside findings/evidence/labels, same one-open()-per-run
        batching as _append_findings."""
        if not contacts:
            return
        with self.contacts_path.open("a", encoding="utf-8") as fh:
            fh.writelines(
                json.dumps(contact_asdict(c), ensure_ascii=False) + "\n"
                for c in contacts
            )

    def _append_evidence(self, result: ModuleResult) -> None:
        entry = {
            "timestamp": utc_now(),
            "module": result.module,
            "target": result.target,
            "ok": result.ok,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "duration_ms": result.duration_ms,
            "finding_count": len(result.findings),
            "error": result.error,
            "options": result.options,
            # The audit trail must never present a replayed response as a live
            # lookup. False whenever the cache is off, which is the default.
            "cached": bool(result.cached_responses),
            "cached_responses": result.cached_responses,
            "max_cache_age_s": (
                round(result.max_cache_age_s, 1) if result.max_cache_age_s is not None else None
            ),
        }
        with self.evidence_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def load_findings(self) -> list[dict]:
        return _read_jsonl(self.findings_path)

    def load_evidence(self) -> list[dict]:
        return _read_jsonl(self.evidence_path)

    def record_label(self, label: str) -> None:
        """Append-only, like findings — dedupe happens at render time, not here."""
        entry = {"label": slugify(label), "added_at": utc_now()}
        with self.labels_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def load_labels(self) -> list[dict]:
        return _read_jsonl(self.labels_path)

    def load_contacts(self) -> list[dict]:
        return _read_jsonl(self.contacts_path)
