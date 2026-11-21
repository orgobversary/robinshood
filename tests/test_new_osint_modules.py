from __future__ import annotations

import httpx

from pathlib import Path

from robinshood.core.types import RunContext
from robinshood.modules.archive import wayback_available
from robinshood.modules.infra import hackertarget_hostsearch
from robinshood.modules.routing import ripestat_abuse, ripestat_routing
from robinshood.modules.threatintel import alienvault_otx


# ── wayback_available ───────────────────────────────────────────────────


def test_wayback_available_finds_a_snapshot(mock_ctx):
    ctx = mock_ctx(
        {
            "archive.org/wayback/available": {
                "archived_snapshots": {
                    "closest": {"available": True, "url": "http://web.archive.org/web/2020/x", "timestamp": "2020"}
                }
            }
        }
    )
    findings = wayback_available.run("https://example.com", ctx)
    assert [f.value for f in findings] == ["http://web.archive.org/web/2020/x"]
    assert findings[0].type == "archived_url"


def test_wayback_available_no_snapshot_is_empty(mock_ctx):
    ctx = mock_ctx({"archive.org/wayback/available": {"archived_snapshots": {}}})
    assert wayback_available.run("https://example.com", ctx) == []


# ── ripestat_routing ─────────────────────────────────────────────────────


def test_ripestat_routing_extracts_prefix_and_asn(mock_ctx):
    ctx = mock_ctx(
        {
            "network-info": {"data": {"asns": ["15169"], "prefix": "8.8.8.0/24"}},
            "as-overview": {"data": {"holder": "GOOGLE"}},
        }
    )
    findings = ripestat_routing.run("8.8.8.8", ctx)
    by_type = {f.type: f.value for f in findings}
    assert by_type == {"prefix": "8.8.8.0/24", "asn": "15169"}
    asn_finding = next(f for f in findings if f.type == "asn")
    assert asn_finding.raw == {"holder": "GOOGLE"}


def test_ripestat_routing_enrichment_failure_is_not_fatal(mock_ctx):
    """The holder-name lookup is a nice-to-have second call — its failure must
    never take down the primary asn/prefix finding."""
    ctx = mock_ctx({"network-info": {"data": {"asns": ["15169"], "prefix": "8.8.8.0/24"}}, "as-overview": 500})
    findings = ripestat_routing.run("8.8.8.8", ctx)
    assert {f.type for f in findings} == {"prefix", "asn"}


def test_ripestat_routing_no_asns_is_prefix_only(mock_ctx):
    ctx = mock_ctx({"network-info": {"data": {"asns": [], "prefix": "8.8.8.0/24"}}})
    findings = ripestat_routing.run("8.8.8.8", ctx)
    assert [f.type for f in findings] == ["prefix"]


# ── ripestat_abuse ───────────────────────────────────────────────────────


def test_ripestat_abuse_extracts_contacts(mock_ctx):
    ctx = mock_ctx({"abuse-contact-finder": {"data": {"abuse_contacts": ["network-abuse@google.com"]}}})
    findings = ripestat_abuse.run("8.8.8.8", ctx)
    assert [f.value for f in findings] == ["network-abuse@google.com"]
    assert findings[0].type == "abuse_contact"


def test_ripestat_abuse_no_contacts_is_empty(mock_ctx):
    ctx = mock_ctx({"abuse-contact-finder": {"data": {"abuse_contacts": []}}})
    assert ripestat_abuse.run("8.8.8.8", ctx) == []


# ── hackertarget_hostsearch ──────────────────────────────────────────────


def _text_ctx(body: str) -> RunContext:
    """hackertarget answers plain text, not JSON — mock_ctx's shared fixture
    always JSON-encodes payloads, so this needs its own transport."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    return RunContext(http=httpx.Client(transport=httpx.MockTransport(handler)), env={})


def test_hackertarget_hostsearch_parses_csv():
    ctx = _text_ctx("mail.example.com,8.8.8.8\nftp.example.com,8.8.8.8\n")
    findings = hackertarget_hostsearch.run("8.8.8.8", ctx)
    assert [f.value for f in findings] == ["mail.example.com", "ftp.example.com"]
    assert all(f.type == "domain" for f in findings)


def test_hackertarget_hostsearch_excludes_the_target_itself():
    """The free tier answers a bare IP,IP echo when nothing else shares the
    server — that's the target, not a finding about it."""
    ctx = _text_ctx("8.8.8.8,8.8.8.8\n")
    assert hackertarget_hostsearch.run("8.8.8.8", ctx) == []


def test_hackertarget_hostsearch_rate_limit_is_a_failure_not_empty():
    """A 200 with an error body must not be silently read as 'no hostnames'."""
    ctx = _text_ctx("error check your search parameter API count exceeded - Increase Rate Limit")
    try:
        hackertarget_hostsearch.run("8.8.8.8", ctx)
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "rate limit" in str(exc).lower()


# ── alienvault_otx ───────────────────────────────────────────────────────


def test_alienvault_otx_extracts_pulses(mock_ctx):
    ctx = mock_ctx({"indicators/domain": {"pulse_info": {"count": 1, "pulses": [{"name": "Phish Kit", "tags": ["x"]}]}}})
    findings = alienvault_otx.run("example.com", ctx)
    assert [f.value for f in findings] == ["Phish Kit"]
    assert findings[0].type == "threat_pulse"


def test_alienvault_otx_no_pulses_is_empty(mock_ctx):
    ctx = mock_ctx({"indicators/domain": {"pulse_info": {"count": 0, "pulses": []}}})
    assert alienvault_otx.run("example.com", ctx) == []


def test_alienvault_otx_collapses_embedded_whitespace(mock_ctx):
    ctx = mock_ctx({"indicators/domain": {"pulse_info": {"count": 1, "pulses": [{"name": "VirusTotal report\n  for x.zip"}]}}})
    findings = alienvault_otx.run("example.com", ctx)
    assert findings[0].value == "VirusTotal report for x.zip"


# ── maigret ──────────────────────────────────────────────────────────────

import json as _json

from robinshood.modules.username import maigret as maigret_module


def _maigret_ctx(ndjson_lines):
    """maigret writes its report to a file in the cwd it's run in (--folderoutput),
    not to stdout — the fake exec has to actually drop that file for the module
    to find, unlike the simpler string-return fakes used elsewhere."""

    def fake_exec(argv, timeout=None, cwd=None):
        report = Path(cwd) / "report_someuser_ndjson.json"
        report.write_text("\n".join(_json.dumps(line) for line in ndjson_lines))
        return ""

    return RunContext(http=httpx.Client(), env={}, exec=fake_exec)


def test_maigret_parses_ndjson_hits():
    ctx = _maigret_ctx([{"sitename": "GitHub", "url_user": "https://github.com/someuser"}])
    findings = maigret_module.run("someuser", ctx)
    assert [f.value for f in findings] == ["https://github.com/someuser"]
    assert findings[0].confidence == "Unverified"
    assert findings[0].raw == {"site": "GitHub"}


def test_maigret_no_report_file_is_empty():
    def fake_exec(argv, timeout=None, cwd=None):
        return ""  # no report written -- e.g. zero hits

    ctx = RunContext(http=httpx.Client(), env={}, exec=fake_exec)
    assert maigret_module.run("someuser", ctx) == []


def test_maigret_rejects_flag_shaped_target():
    ctx = _maigret_ctx([])
    try:
        maigret_module.run("--not-a-username", ctx)
        assert False, "expected ValueError from safe_target"
    except ValueError:
        pass


# ── numlookup_phone ──────────────────────────────────────────────────────

from robinshood.modules.phone import numlookup_phone


def test_numlookup_phone_extracts_carrier_line_type_geo(mock_ctx):
    ctx = mock_ctx(
        {
            "numlookupapi.com/v1/validate": {
                "valid": True,
                "carrier": "AT&T Mobility LLC",
                "line_type": "mobile",
                "location": "Novato",
                "country_name": "United States of America",
                "country_code": "US",
            }
        },
        env={"NUMLOOKUP_API_KEY": "key"},
    )
    findings = numlookup_phone.run("+14158586273", ctx)
    by_type = {f.type: f.value for f in findings}
    assert by_type == {
        "carrier": "AT&T Mobility LLC",
        "line_type": "mobile",
        "geo": "Novato, United States of America",
    }


def test_numlookup_phone_invalid_number_is_empty(mock_ctx):
    ctx = mock_ctx(
        {"numlookupapi.com/v1/validate": {"valid": False, "line_type": "N/A"}},
        env={"NUMLOOKUP_API_KEY": "key"},
    )
    assert numlookup_phone.run("+10000000000", ctx) == []


def test_numlookup_phone_missing_key_raises():
    ctx = RunContext(http=httpx.Client(), env={})
    try:
        numlookup_phone.run("+14158586273", ctx)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "NUMLOOKUP_API_KEY" in str(exc)


def test_numlookup_phone_na_line_type_is_dropped(mock_ctx):
    """'N/A' is the API's own placeholder for unknown, not a real line type."""
    ctx = mock_ctx(
        {"numlookupapi.com/v1/validate": {"valid": True, "line_type": "N/A", "carrier": "Some Carrier"}},
        env={"NUMLOOKUP_API_KEY": "key"},
    )
    findings = numlookup_phone.run("+14158586273", ctx)
    assert {f.type for f in findings} == {"carrier"}
