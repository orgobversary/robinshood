from __future__ import annotations

import pytest

from robinshood.core.case import Case
from robinshood.core.export import (
    ExportError,
    attach_note,
    export_case,
    notes_slug,
    render_note,
)
from robinshood.core.types import Finding, ModuleResult


def _seed(root, target="example.com"):
    case = Case.open(root, target)
    case.record_result(
        ModuleResult(
            module="dns_doh",
            target=target,
            ok=True,
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            duration_ms=1000.0,
            findings=[Finding(type="ip", value="93.184.216.34", module="dns_doh", target=target)],
        )
    )
    return case


def test_notes_slug_is_derived_from_case_slug():
    assert notes_slug("example-com") == "example-com-notes"


def test_creates_note_with_frontmatter_and_backlink(tmp_path):
    path = attach_note(tmp_path, "example-com", "First look", "Cloudflare fronted.")
    text = path.read_text(encoding="utf-8")
    assert path.name == "example-com-notes.md"
    assert "case: example-com" in text
    assert "type: analysis" in text
    assert "Case: [[example-com]]" in text
    assert "## First look" in text
    assert "Cloudflare fronted." in text


def test_companion_note_is_not_marked_as_generated(tmp_path):
    """It must never look like a generated note, or export would overwrite it."""
    path = attach_note(tmp_path, "example-com", "T", "B")
    assert "generator: robinshood" not in path.read_text(encoding="utf-8")


def test_second_note_appends_and_preserves_the_first(tmp_path):
    attach_note(tmp_path, "example-com", "First", "Original analysis.")
    path = attach_note(tmp_path, "example-com", "Second", "Later thoughts.")
    text = path.read_text(encoding="utf-8")
    assert "Original analysis." in text
    assert "Later thoughts." in text
    assert text.count("case: example-com") == 1  # frontmatter written once


def test_title_only_is_allowed(tmp_path):
    path = attach_note(tmp_path, "example-com", "Just a heading", "")
    assert "## Just a heading" in path.read_text(encoding="utf-8")


def test_body_only_gets_a_default_heading(tmp_path):
    path = attach_note(tmp_path, "example-com", "", "Some text.")
    text = path.read_text(encoding="utf-8")
    assert "## Note" in text
    assert "Some text." in text


def test_empty_note_is_rejected(tmp_path):
    with pytest.raises(ExportError, match="title or a body"):
        attach_note(tmp_path, "example-com", "   ", "  ")


def test_unsafe_case_name_is_rejected(tmp_path):
    with pytest.raises(ExportError, match="unsafe case name"):
        attach_note(tmp_path, "../escape", "T", "B")


def test_timestamp_is_recorded(tmp_path):
    path = attach_note(tmp_path, "example-com", "T", "B", timestamp="2026-05-05T12:00:00Z")
    assert "2026-05-05T12:00:00Z" in path.read_text(encoding="utf-8")


# ── interaction with export ───────────────────────────────────

def test_generated_note_links_to_its_companion(tmp_path):
    case = _seed(tmp_path)
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "[[example-com-notes]]" in note


def test_companion_link_is_present_even_when_no_note_exists(tmp_path):
    """The link must not depend on vault state, or rendering stops being
    deterministic."""
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    before = export_case(case, vault).read_bytes()
    attach_note(vault, case.slug, "Now it exists", "body")
    after = export_case(case, vault).read_bytes()
    assert before == after


def test_export_does_not_touch_the_companion_note(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    companion = attach_note(vault, case.slug, "Mine", "Hand-written analysis.")
    original = companion.read_bytes()

    export_case(case, vault)
    export_case(case, vault)

    assert companion.read_bytes() == original
    assert "Hand-written analysis." in companion.read_text(encoding="utf-8")


def test_companion_note_survives_a_forced_export(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    companion = attach_note(vault, case.slug, "Mine", "Keep me.")
    export_case(case, vault, force=True)
    assert "Keep me." in companion.read_text(encoding="utf-8")


def test_export_writes_only_the_generated_note(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    export_case(case, vault)
    assert sorted(p.name for p in vault.iterdir()) == ["example-com.md"]
