from __future__ import annotations

import pytest

from robinshood.core.case import Case
from robinshood.core.export import (
    ExportError,
    default_limit,
    export_case,
    human_bytes,
    preview_case,
    render_note,
)
from robinshood.core.egress import ContactEvent
from robinshood.core.types import Finding, ModuleResult


def _result(module, target, findings):
    return ModuleResult(
        module=module,
        target=target,
        ok=True,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:02Z",
        duration_ms=2000.0,
        findings=findings,
    )


def _seed(root, target="example.com", n=120):
    case = Case.open(root, target)
    case.record_result(
        _result(
            "dns_doh",
            target,
            [Finding(type="ip", value="93.184.216.34", module="dns_doh", target=target)],
        )
    )
    case.record_result(
        _result(
            "subfinder",
            target,
            [
                Finding(type="domain", value=f"h{i}.example.com", module="subfinder", target=target)
                for i in range(n)
            ],
        )
    )
    return case


# ── determinism ───────────────────────────────────────────────

def test_render_is_byte_identical_across_calls(tmp_path):
    case = _seed(tmp_path)
    a = render_note(case.slug, case.load_findings(), case.load_evidence())
    b = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert a == b


def test_render_with_contacts_is_byte_identical_across_calls(tmp_path):
    """Outbound-contacts rendering reads contacts.jsonl in file order with no
    dedup/sort step -- same determinism guarantee as the Runs table, since the
    source file itself is fixed at export time."""
    case = _seed(tmp_path)
    result = _result("dns_doh", "example.com", [])
    result.contacts = [
        ContactEvent(timestamp="t", module="dns_doh", kind="http", destination="https://dns.google/resolve"),
        ContactEvent(timestamp="t2", module="dns_doh", kind="http", destination="https://dns.google/resolve2"),
    ]
    case.record_result(result)

    a = render_note(case.slug, case.load_findings(), case.load_evidence(), contacts=case.load_contacts())
    b = render_note(case.slug, case.load_findings(), case.load_evidence(), contacts=case.load_contacts())
    assert a == b
    assert a.count("dns.google/resolve") == 2  # both distinct URLs present, in file order


def test_export_is_byte_identical_across_runs(tmp_path):
    """Re-exporting an unchanged case must not churn the vault — otherwise every
    export dirties git history and Obsidian sync for no reason."""
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    first = export_case(case, vault).read_bytes()
    second = export_case(case, vault).read_bytes()
    assert first == second


def test_render_carries_no_generation_timestamp(tmp_path):
    """A 'generated at' stamp would make every export differ. Timestamps in the
    note must come only from the recorded runs."""
    case = _seed(tmp_path)
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert note.count("2026-01-01T00:00:00Z") >= 1
    assert "generated_at" not in note


def test_known_slug_set_order_does_not_affect_output(tmp_path):
    """known_slugs is a set; iteration order must never leak into the note."""
    case = _seed(tmp_path, n=5)
    slugs_a = {"h1-example-com", "h3-example-com", "h4-example-com"}
    slugs_b = {"h4-example-com", "h1-example-com", "h3-example-com"}
    a = render_note(case.slug, case.load_findings(), case.load_evidence(), known_slugs=slugs_a)
    b = render_note(case.slug, case.load_findings(), case.load_evidence(), known_slugs=slugs_b)
    assert a == b


def test_module_list_is_sorted_not_insertion_ordered(tmp_path):
    case = Case.open(tmp_path, "example.com")
    for module in ("subfinder", "dns_doh", "rdap_domain"):
        case.record_result(
            _result(
                module,
                "example.com",
                [Finding(type="ip", value="1.1.1.1", module=module, target="example.com")],
            )
        )
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "modules: [dns_doh, rdap_domain, subfinder]" in note


def test_export_creates_no_directories_beyond_the_vault(tmp_path):
    """Flat notes only — labels live in frontmatter, never in a folder tree."""
    vault = tmp_path / "vault"
    for target in ("example.com", "8.8.8.8", "torvalds"):
        export_case(_seed(tmp_path / "cases", target=target, n=2), vault)
    entries = sorted(p.name for p in vault.iterdir())
    assert entries == ["8-8-8-8.md", "example-com.md", "torvalds.md"]
    assert all(p.is_file() for p in vault.iterdir())


# ── configurable limit ────────────────────────────────────────

def test_default_limit_falls_back_to_50():
    assert default_limit({}) == 50


def test_default_limit_reads_env():
    assert default_limit({"ROBINSHOOD_EXPORT_LIMIT": "5"}) == 5


def test_default_limit_zero_means_unlimited():
    assert default_limit({"ROBINSHOOD_EXPORT_LIMIT": "0"}) == 0


def test_default_limit_ignores_blank():
    assert default_limit({"ROBINSHOOD_EXPORT_LIMIT": "  "}) == 50


@pytest.mark.parametrize("bad", ["abc", "1.5", "-3"])
def test_default_limit_rejects_bad_values(bad):
    with pytest.raises(ExportError):
        default_limit({"ROBINSHOOD_EXPORT_LIMIT": bad})


@pytest.mark.parametrize("limit,expected_shown", [(1, 1), (10, 10), (500, 120), (0, 120)])
def test_limit_controls_how_much_reaches_the_vault(tmp_path, limit, expected_shown):
    case = _seed(tmp_path, n=120)
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), limit=limit)
    inlined = sum(1 for line in note.splitlines() if line.startswith("- `h"))
    assert inlined == expected_shown


# ── preview ───────────────────────────────────────────────────

def test_preview_matches_what_export_writes(tmp_path):
    """The previewed byte count must equal the file actually written, or the
    preview is worse than useless."""
    case = _seed(tmp_path / "cases", n=300)
    vault = tmp_path / "vault"
    preview = preview_case(case, vault, limit=50)
    written = export_case(case, vault, limit=50)
    assert preview.note_bytes == len(written.read_bytes())


def test_preview_writes_nothing(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    preview_case(case, vault)
    assert not vault.exists()


def test_preview_counts_total_and_inlined_separately(tmp_path):
    case = _seed(tmp_path / "cases", n=300)
    preview = preview_case(case, tmp_path / "vault", limit=50)
    assert preview.finding_count == 301  # 300 domains + 1 ip
    assert preview.shown_count == 51     # 50 domains + 1 ip


def test_preview_reports_new_then_overwrite(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    assert preview_case(case, vault).status == "new"
    export_case(case, vault)
    assert preview_case(case, vault).status == "overwrite"


def test_preview_flags_a_note_it_would_not_overwrite(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "example-com.md").write_text("hand written\n", encoding="utf-8")
    preview = preview_case(case, vault)
    assert not preview.ok
    assert "not ours" in preview.status


def test_preview_grows_with_limit(tmp_path):
    case = _seed(tmp_path / "cases", n=500)
    vault = tmp_path / "vault"
    small = preview_case(case, vault, limit=10).note_bytes
    large = preview_case(case, vault, limit=0).note_bytes
    assert large > small * 5


@pytest.mark.parametrize(
    "n,expected",
    [(512, "512 B"), (2048, "2.0 KB"), (1024 * 1024 * 3, "3.0 MB")],
)
def test_human_bytes(n, expected):
    assert human_bytes(n) == expected


# ── Unverified warning callout ───────────────────────────────────

def test_render_flags_unverified_findings_with_warning_callout(tmp_path):
    case = Case.open(tmp_path, "obversarystudios.org")
    case.record_result(
        _result(
            "sherlock",
            "obversarystudios.org",
            [
                Finding(type="profile", value="https://x.com/a", module="sherlock",
                        target="obversarystudios.org", confidence="Unverified"),
                Finding(type="profile", value="https://x.com/b", module="sherlock",
                        target="obversarystudios.org", confidence="Unverified"),
            ],
        )
    )
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "> [!warning] 2 finding(s) below are Unverified" in note


def test_render_omits_warning_callout_when_no_unverified_findings(tmp_path):
    case = _seed(tmp_path)
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "[!warning]" not in note


def test_warning_callout_count_is_unaffected_by_limit(tmp_path):
    case = Case.open(tmp_path, "obversarystudios.org")
    case.record_result(
        _result(
            "sherlock",
            "obversarystudios.org",
            [
                Finding(type="profile", value=f"https://x.com/{i}", module="sherlock",
                        target="obversarystudios.org", confidence="Unverified")
                for i in range(30)
            ],
        )
    )
    full = render_note(case.slug, case.load_findings(), case.load_evidence(), limit=0)
    capped = render_note(case.slug, case.load_findings(), case.load_evidence(), limit=5)
    assert "> [!warning] 30 finding(s)" in full
    assert "> [!warning] 30 finding(s)" in capped


# ── custom labels ─────────────────────────────────────────────────

def test_render_includes_sorted_labels(tmp_path):
    case = _seed(tmp_path)
    case.record_label("bug-bounty")
    case.record_label("Client Work")
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), labels=case.load_labels())
    assert "labels: [bug-bounty, client-work]" in note


def test_render_labels_empty_when_none_added(tmp_path):
    case = _seed(tmp_path)
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), labels=case.load_labels())
    assert "labels: []" in note


def test_render_duplicate_label_adds_collapse(tmp_path):
    case = _seed(tmp_path)
    case.record_label("bug-bounty")
    case.record_label("bug-bounty")
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), labels=case.load_labels())
    assert "labels: [bug-bounty]" in note


def test_existing_tags_field_is_untouched_by_labels(tmp_path):
    case = _seed(tmp_path)
    case.record_label("bug-bounty")
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), labels=case.load_labels())
    assert "tags: [recon/domain]" in note


# ── structured frontmatter fields (categories / finding_types / passive_only) ──

_MODULE_INFO = {
    "dns_doh": ("dns", True),
    "subfinder": ("subdomain", True),
    "httpx_probe": ("infra", False),
    "photon": ("crawl", False),
}


def test_render_includes_categories_and_finding_types(tmp_path):
    case = _seed(tmp_path, n=3)
    note = render_note(
        case.slug, case.load_findings(), case.load_evidence(), module_info=_MODULE_INFO
    )
    assert "categories: [dns, subdomain]" in note
    assert "finding_types: [domain, ip]" in note
    assert "record_type: case" in note


def test_render_passive_only_true_when_every_module_is_passive(tmp_path):
    case = _seed(tmp_path, n=1)
    note = render_note(
        case.slug, case.load_findings(), case.load_evidence(), module_info=_MODULE_INFO
    )
    assert "passive_only: true" in note


def test_render_passive_only_false_when_an_active_module_ran(tmp_path):
    case = _seed(tmp_path, n=1)
    case.record_result(
        _result(
            "httpx_probe",
            "example.com",
            [Finding(type="url", value="https://example.com", module="httpx_probe", target="example.com")],
        )
    )
    note = render_note(
        case.slug, case.load_findings(), case.load_evidence(), module_info=_MODULE_INFO
    )
    assert "passive_only: false" in note


def test_render_has_unverified_field_matches_callout(tmp_path):
    case = _seed(tmp_path, n=1)
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "has_unverified: false" in note

    case.record_result(
        _result(
            "sherlock",
            "example.com",
            [Finding(type="profile", value="https://x.com/a", module="sherlock",
                     target="example.com", confidence="Unverified")],
        )
    )
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "has_unverified: true" in note


def test_render_unknown_module_falls_back_gracefully(tmp_path):
    """A module absent from module_info (e.g. since removed/renamed) must not
    raise, and must not silently claim the case is passive-only."""
    case = _seed(tmp_path, n=1)
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), module_info={})
    assert "categories: [unknown]" in note
    assert "passive_only: false" in note
