from __future__ import annotations

from robinshood.core.case import Case, slugify
from robinshood.core.types import Finding, ModuleResult


def _result(findings):
    return ModuleResult(
        module="dns_doh",
        target="example.com",
        ok=True,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        duration_ms=1000.0,
        findings=findings,
    )


def test_slugify():
    assert slugify("Example.COM") == "example-com"
    assert slugify("  8.8.8.8 ") == "8-8-8-8"
    assert slugify("!!!") == "case"


def test_record_and_reload_round_trip(tmp_path):
    case = Case.open(tmp_path, "example.com")
    findings = [
        Finding(type="ip", value="93.184.216.34", module="dns_doh", target="example.com"),
        Finding(type="ns", value="a.iana-servers.net", module="dns_doh", target="example.com"),
    ]
    case.record_result(_result(findings))

    reloaded = Case.open(tmp_path, "example.com")
    loaded = reloaded.load_findings()
    assert [f["value"] for f in loaded] == ["93.184.216.34", "a.iana-servers.net"]

    evidence = reloaded.load_evidence()
    assert len(evidence) == 1
    assert evidence[0]["module"] == "dns_doh"
    assert evidence[0]["finding_count"] == 2


def test_appends_across_runs(tmp_path):
    case = Case.open(tmp_path, "example.com")
    case.record_result(_result([Finding(type="ip", value="1.1.1.1", module="m", target="t")]))
    case.record_result(_result([Finding(type="ip", value="2.2.2.2", module="m", target="t")]))
    assert len(case.load_findings()) == 2
    assert len(case.load_evidence()) == 2


def test_record_and_load_labels_round_trip(tmp_path):
    case = Case.open(tmp_path, "obversarystudios.org")
    case.record_label("bug-bounty")
    case.record_label("client work")  # slugified on write

    reloaded = Case.open(tmp_path, "obversarystudios.org")
    labels = [row["label"] for row in reloaded.load_labels()]
    assert labels == ["bug-bounty", "client-work"]


def test_load_labels_empty_when_none_added(tmp_path):
    case = Case.open(tmp_path, "obversarystudios.org")
    assert case.load_labels() == []


def test_failed_run_still_logs_evidence(tmp_path):
    case = Case.open(tmp_path, "example.com")
    failed = ModuleResult(
        module="rdap_ip",
        target="8.8.8.8",
        ok=False,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        duration_ms=5.0,
        error="HTTPError: boom",
    )
    case.record_result(failed)
    evidence = case.load_evidence()
    assert evidence[0]["ok"] is False
    assert "boom" in evidence[0]["error"]
    assert case.load_findings() == []


def test_bulk_findings_written_in_one_open(tmp_path, monkeypatch):
    """One open() per run, not per finding — a subdomain sweep emits tens of
    thousands, and per-finding opens turned one append into 25k syscalls."""
    case = Case.open(tmp_path, "example.com")
    findings = [
        Finding(type="domain", value=f"host{i}.example.com", module="subfinder", target="example.com")
        for i in range(500)
    ]

    real_open = type(case.findings_path).open
    opens = []

    def counting_open(self, *args, **kwargs):
        if self == case.findings_path:
            opens.append(args[0] if args else kwargs.get("mode", "r"))
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(type(case.findings_path), "open", counting_open)
    case.record_result(_result(findings))

    assert opens == ["a"]
    assert [f["value"] for f in case.load_findings()] == [f.value for f in findings]


def test_empty_findings_never_creates_the_file(tmp_path):
    """A run with no findings is absent data, not a reason to touch the file."""
    case = Case.open(tmp_path, "example.com")
    case.record_result(_result([]))
    assert not case.findings_path.exists()
    assert len(case.load_evidence()) == 1


def test_blank_lines_in_jsonl_are_skipped(tmp_path):
    """Files are hand-editable by design, so a stray newline must not break a load."""
    case = Case.open(tmp_path, "example.com")
    case.record_result(_result([Finding(type="ip", value="1.1.1.1", module="m", target="t")]))
    case.findings_path.write_text(case.findings_path.read_text() + "\n\n")
    assert len(case.load_findings()) == 1


# ── contacts.jsonl ───────────────────────────────────────────────────────

from robinshood.core.egress import ContactEvent


def _result_with_contacts(contacts):
    r = _result([])
    r.contacts = contacts
    return r


def test_contacts_are_recorded_and_reloaded(tmp_path):
    case = Case.open(tmp_path, "example.com")
    contact = ContactEvent(
        timestamp="2026-01-01T00:00:00Z", module="dns_doh", kind="http",
        destination="https://dns.google/resolve?name=example.com", proxy=None,
        user_agent="robinshood/0.1", tor_rotated=False, status="200",
    )
    case.record_result(_result_with_contacts([contact]))

    reloaded = Case.open(tmp_path, "example.com")
    contacts = reloaded.load_contacts()
    assert len(contacts) == 1
    assert contacts[0]["module"] == "dns_doh"
    assert contacts[0]["status"] == "200"


def test_no_contacts_never_creates_the_file(tmp_path):
    """Egress logging isn't wired up for every call site (yet) -- an empty
    contacts list must behave like an empty findings list, not an error."""
    case = Case.open(tmp_path, "example.com")
    case.record_result(_result_with_contacts([]))
    assert not case.contacts_path.exists()
    assert case.load_contacts() == []


def test_contacts_append_across_runs(tmp_path):
    case = Case.open(tmp_path, "example.com")
    c1 = ContactEvent(timestamp="t1", module="m1", kind="http", destination="d1")
    c2 = ContactEvent(timestamp="t2", module="m2", kind="cli", destination="d2")
    case.record_result(_result_with_contacts([c1]))
    case.record_result(_result_with_contacts([c2]))
    assert len(case.load_contacts()) == 2
