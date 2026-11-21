from __future__ import annotations

import pytest

from robinshood.core.case import Case, list_cases
from robinshood.core.export import ExportError, export_case, render_note
from robinshood.core.types import Finding, ModuleResult


def _result(module, target, findings, ok=True, error=None):
    return ModuleResult(
        module=module,
        target=target,
        ok=ok,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:02Z",
        duration_ms=2000.0,
        findings=findings,
        error=error,
    )


def _seed(tmp_path, target="example.com", n_domains=0):
    case = Case.open(tmp_path, target)
    findings = [
        Finding(type="ip", value="93.184.216.34", module="dns_doh", target=target),
        Finding(type="ns", value="a.iana-servers.net", module="dns_doh", target=target),
    ]
    case.record_result(_result("dns_doh", target, findings))
    if n_domains:
        subs = [
            Finding(type="domain", value=f"h{i}.example.com", module="subfinder", target=target)
            for i in range(n_domains)
        ]
        case.record_result(_result("subfinder", target, subs))
    return case


# ── frontmatter ───────────────────────────────────────────────

def test_frontmatter_carries_generator_marker(tmp_path):
    case = _seed(tmp_path)
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert note.startswith("---\n")
    assert "generator: robinshood" in note
    assert 'target: "example.com"' in note
    assert "target_type: domain" in note
    assert "tags: [recon/domain]" in note


def test_frontmatter_counts_unique_findings(tmp_path):
    case = _seed(tmp_path)
    # re-running the same module appends duplicates; the note must collapse them
    case.record_result(
        _result(
            "dns_doh",
            "example.com",
            [Finding(type="ip", value="93.184.216.34", module="dns_doh", target="example.com")],
        )
    )
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "finding_count: 2" in note
    assert note.count("- `93.184.216.34`") == 1


def test_yaml_special_characters_are_escaped(tmp_path):
    case = Case.open(tmp_path, 'weird" target')
    case.record_result(
        _result(
            "dns_doh",
            'weird" target',
            [Finding(type="ip", value="1.1.1.1", module="dns_doh", target='weird" target')],
        )
    )
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert r'target: "weird\" target"' in note


# ── volume ────────────────────────────────────────────────────

def test_findings_are_capped_by_default(tmp_path):
    case = _seed(tmp_path, n_domains=500)
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), limit=50)
    assert note.count("h0.example.com") == 1
    assert "h49.example.com" in note
    assert "h50.example.com" not in note
    assert "450 more not shown" in note


def test_limit_zero_inlines_everything(tmp_path):
    case = _seed(tmp_path, n_domains=120)
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), limit=0)
    assert "h119.example.com" in note
    assert "more not shown" not in note


def test_group_header_shows_true_total_not_shown_count(tmp_path):
    case = _seed(tmp_path, n_domains=500)
    note = render_note(case.slug, case.load_findings(), case.load_evidence(), limit=50)
    assert "## domain (500)" in note


# ── runs and failures ─────────────────────────────────────────

def test_failed_run_appears_with_its_error(tmp_path):
    case = Case.open(tmp_path, "example.com")
    case.record_result(
        _result("subfinder", "example.com", [], ok=False, error="RuntimeError: not on PATH")
    )
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "### Failed runs" in note
    assert "not on PATH" in note
    assert "No findings recorded." in note


def test_empty_result_is_distinct_from_failure(tmp_path):
    """A module that ran fine and found nothing must not look like a failure."""
    case = Case.open(tmp_path, "example.com")
    case.record_result(_result("subfinder", "example.com", []))
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "### Failed runs" not in note
    assert "| `subfinder` | yes | 0 |" in note


# ── wiki links ────────────────────────────────────────────────

def test_finding_matching_another_case_becomes_a_wikilink(tmp_path):
    case = _seed(tmp_path, n_domains=3)
    note = render_note(
        case.slug,
        case.load_findings(),
        case.load_evidence(),
        known_slugs={"h1-example-com"},
    )
    assert "[[h1-example-com|h1.example.com]]" in note
    assert "`h0.example.com`" in note  # unknown target stays plain


def test_note_never_links_to_itself(tmp_path):
    """A finding value equal to the case's own target must stay plain text. The
    companion-note link ([[<slug>-notes]]) is separate and expected."""
    case = _seed(tmp_path)
    note = render_note(
        case.slug, case.load_findings(), case.load_evidence(), known_slugs={case.slug}
    )
    assert f"[[{case.slug}|" not in note
    assert f"[[{case.slug}]]" not in note


# ── confidence ────────────────────────────────────────────────

def test_non_default_confidence_is_surfaced(tmp_path):
    case = Case.open(tmp_path, "torvalds")
    case.record_result(
        _result(
            "sherlock",
            "torvalds",
            [
                Finding(
                    type="profile",
                    value="https://github.com/torvalds",
                    module="sherlock",
                    target="torvalds",
                    confidence="Unverified",
                )
            ],
        )
    )
    note = render_note(case.slug, case.load_findings(), case.load_evidence())
    assert "*Unverified*" in note


# ── write path and safety ─────────────────────────────────────

def test_export_writes_note_named_for_the_case(tmp_path):
    case = _seed(tmp_path / "cases")
    out = export_case(case, tmp_path / "vault")
    assert out.name == "example-com.md"
    assert out.read_text(encoding="utf-8").startswith("---")


def test_export_refuses_to_overwrite_a_handwritten_note(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    vault.mkdir()
    note = vault / "example-com.md"
    note.write_text("---\ntitle: mine\n---\n\nMy own analysis.\n", encoding="utf-8")

    with pytest.raises(ExportError, match="refusing to overwrite"):
        export_case(case, vault)
    assert "My own analysis." in note.read_text(encoding="utf-8")


def test_export_overwrites_its_own_note(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    first = export_case(case, vault)
    second = export_case(case, vault)
    assert first == second


def test_force_overwrites_a_handwritten_note(tmp_path):
    case = _seed(tmp_path / "cases")
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "example-com.md").write_text("mine\n", encoding="utf-8")
    out = export_case(case, vault, force=True)
    assert "generator: robinshood" in out.read_text(encoding="utf-8")


def test_export_rejects_unsafe_case_name(tmp_path):
    case = _seed(tmp_path / "cases")
    case.slug = "../escape"
    with pytest.raises(ExportError, match="unsafe name"):
        export_case(case, tmp_path / "vault")


def test_export_rejects_empty_case(tmp_path):
    case = Case.open(tmp_path / "cases", "nothing")
    with pytest.raises(ExportError, match="nothing to export"):
        export_case(case, tmp_path / "vault")


# ── case discovery ────────────────────────────────────────────

def test_list_cases_finds_seeded_cases(tmp_path):
    _seed(tmp_path, target="example.com")
    _seed(tmp_path, target="8.8.8.8")
    assert list_cases(tmp_path) == ["8-8-8-8", "example-com"]


def test_list_cases_ignores_unrelated_directories(tmp_path):
    _seed(tmp_path, target="example.com")
    (tmp_path / "not-a-case").mkdir()
    assert list_cases(tmp_path) == ["example-com"]


def test_list_cases_on_missing_root(tmp_path):
    assert list_cases(tmp_path / "nope") == []


# ── outbound contacts section ────────────────────────────────────────────


def test_render_note_lists_outbound_contacts():
    contacts = [
        {
            "timestamp": "2026-01-01T00:00:00Z", "module": "dns_doh", "kind": "http",
            "destination": "https://dns.google/resolve?name=example.com", "proxy": None,
            "user_agent": "robinshood/0.1", "tor_rotated": False, "status": "200", "error": None,
        }
    ]
    note = render_note("example-com", [], [{"module": "dns_doh", "target": "example.com", "started_at": "t"}], contacts=contacts)
    assert "## Outbound contacts" in note
    assert "dns_doh" in note
    assert "https://dns.google/resolve?name=example.com" in note


def test_render_note_without_contacts_says_none_recorded():
    """Egress logging isn't necessarily wired up for every call site -- an
    absent/empty list must render cleanly, not as a missing section."""
    note = render_note("example-com", [], [{"module": "dns_doh", "target": "example.com", "started_at": "t"}])
    assert "## Outbound contacts" in note
    assert "No outbound contacts recorded." in note


def test_render_note_marks_a_failed_contact():
    contacts = [
        {
            "timestamp": "t", "module": "dns_doh", "kind": "http", "destination": "https://x/",
            "proxy": None, "user_agent": None, "tor_rotated": False, "status": "error",
            "error": "ConnectError: refused",
        }
    ]
    note = render_note("example-com", [], [{"module": "dns_doh", "target": "example.com", "started_at": "t"}], contacts=contacts)
    assert "ConnectError: refused" in note


def test_render_note_shows_proxy_and_tor_state():
    contacts = [
        {
            "timestamp": "t", "module": "m", "kind": "http", "destination": "https://x/",
            "proxy": "socks5h://127.0.0.1:9050", "user_agent": None, "tor_rotated": True, "status": "200",
            "error": None,
        }
    ]
    note = render_note("example-com", [], [{"module": "m", "target": "example.com", "started_at": "t"}], contacts=contacts)
    assert "socks5h://127.0.0.1:9050" in note
    section = note.split("## Outbound contacts")[1].split("## Analysis")[0]
    assert "| yes |" in section
