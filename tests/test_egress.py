from __future__ import annotations

import httpx

from robinshood.core.egress import (
    ContactEvent,
    EgressLog,
    EgressLoggingTransport,
    contact_asdict,
    logged_exec,
)
from robinshood.core.runner import run_module
from robinshood.core.registry import RegisteredModule
from robinshood.core.types import Finding, ModuleSpec, RunContext


def _client(handler, log, proxy=None, user_agent="ua/1"):
    inner = httpx.MockTransport(handler)
    transport = EgressLoggingTransport(inner, log, proxy, user_agent)
    return httpx.Client(transport=transport)


# ── EgressLoggingTransport ───────────────────────────────────────────────


def test_successful_request_is_logged_with_status():
    log = EgressLog()
    log.current_module = "dns_doh"
    with _client(lambda r: httpx.Response(200), log) as client:
        client.get("https://example.com/a")
    assert len(log.events) == 1
    event = log.events[0]
    assert event.module == "dns_doh"
    assert event.kind == "http"
    assert event.destination == "https://example.com/a"
    assert event.status == "200"
    assert event.user_agent == "ua/1"
    assert event.error is None


def test_failed_connection_is_logged_and_reraised():
    log = EgressLog()
    log.current_module = "dns_doh"

    def boom(request):
        raise httpx.ConnectError("refused")

    with _client(boom, log) as client:
        try:
            client.get("https://example.com/a")
            assert False, "expected ConnectError"
        except httpx.ConnectError:
            pass
    assert log.events[0].status == "error"
    assert "ConnectError" in log.events[0].error


def test_proxy_and_tor_state_are_recorded():
    log = EgressLog()
    log.current_module = "m"
    log.current_tor_rotated = True
    with _client(lambda r: httpx.Response(200), log, proxy="socks5h://127.0.0.1:9050") as client:
        client.get("https://example.com/a")
    event = log.events[0]
    assert event.proxy == "socks5h://127.0.0.1:9050"
    assert event.tor_rotated is True


def test_current_module_can_change_between_requests_on_one_client():
    """A single client (and log) can outlive many separate runs -- the TUI
    reuses one across every module the user selects in a session."""
    log = EgressLog()
    with _client(lambda r: httpx.Response(200), log) as client:
        log.current_module = "first"
        client.get("https://example.com/a")
        log.current_module = "second"
        client.get("https://example.com/b")
    assert [e.module for e in log.events] == ["first", "second"]


def test_query_secrets_are_redacted():
    log = EgressLog()
    log.current_module = "numlookup_phone"
    with _client(lambda r: httpx.Response(200), log) as client:
        client.get("https://api.numlookupapi.com/v1/validate/123", params={"apikey": "supersecret"})
    assert "supersecret" not in log.events[0].destination
    assert "apikey=REDACTED" in log.events[0].destination


def test_non_secret_query_params_are_preserved():
    log = EgressLog()
    log.current_module = "dns_doh"
    with _client(lambda r: httpx.Response(200), log) as client:
        client.get("https://dns.google/resolve", params={"name": "example.com", "type": "A"})
    assert "name=example.com" in log.events[0].destination
    assert "type=A" in log.events[0].destination


def test_case_insensitive_secret_param_names_are_redacted():
    log = EgressLog()
    log.current_module = "m"
    with _client(lambda r: httpx.Response(200), log) as client:
        client.get("https://example.com/a", params={"ApiKey": "shh", "Token": "shh2"})
    dest = log.events[0].destination
    assert "shh" not in dest
    assert "shh2" not in dest


# ── logged_exec ──────────────────────────────────────────────────────────


def test_logged_exec_records_a_cli_contact():
    log = EgressLog()
    log.current_module = "sherlock"
    wrapped = logged_exec(lambda argv, timeout=None, cwd=None: "output", log, proxy=None)
    result = wrapped(["sherlock", "someuser"], timeout=10)
    assert result == "output"
    assert log.events == [
        ContactEvent(
            timestamp=log.events[0].timestamp, module="sherlock", kind="cli",
            destination="sherlock", proxy=None, tor_rotated=False, status="ok", error=None,
        )
    ]


def test_logged_exec_records_and_reraises_a_failure():
    log = EgressLog()
    log.current_module = "sherlock"

    def boom(argv, timeout=None, cwd=None):
        raise RuntimeError("binary not found")

    wrapped = logged_exec(boom, log, proxy=None)
    try:
        wrapped(["sherlock", "x"])
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass
    assert log.events[0].status == "error"
    assert "binary not found" in log.events[0].error


def test_logged_exec_never_logs_the_binarys_own_arguments():
    """robinshood can't see what the binary itself contacts -- only that it
    was invoked. Logging full argv would also risk leaking anything sensitive
    passed as a CLI flag."""
    log = EgressLog()
    log.current_module = "m"
    wrapped = logged_exec(lambda argv, timeout=None, cwd=None: "", log, proxy=None)
    wrapped(["sherlock", "secretusername", "--timeout", "10"])
    assert log.events[0].destination == "sherlock"


# ── runner delta-snapshot ────────────────────────────────────────────────


def _entry_with_http_call():
    spec = ModuleSpec(name="fake", category="test", description="", consumes="domain", produces=("ip",))

    def run(target, ctx):
        ctx.http.get("https://example.com/a")
        return [Finding(type="ip", value="1.1.1.1", module="fake", target=target)]

    return RegisteredModule(spec=spec, run=run)


def test_run_module_attributes_contacts_to_the_right_result():
    log = EgressLog()
    with _client(lambda r: httpx.Response(200), log) as client:
        ctx = RunContext(http=client, env={}, egress_log=log)
        first = run_module(_entry_with_http_call(), "example.com", ctx)
        second = run_module(_entry_with_http_call(), "example.com", ctx)
    assert len(first.contacts) == 1
    assert len(second.contacts) == 1
    assert first.contacts[0] is not second.contacts[0]


def test_run_module_sets_current_module_automatically():
    """The caller never has to set current_module itself -- run_module does
    it from entry.spec.name before calling run()."""
    log = EgressLog()
    with _client(lambda r: httpx.Response(200), log) as client:
        ctx = RunContext(http=client, env={}, egress_log=log)
        run_module(_entry_with_http_call(), "example.com", ctx)
    assert log.events[0].module == "fake"


def test_no_egress_log_means_no_contacts_not_a_crash():
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as client:
        ctx = RunContext(http=client, env={})
        result = run_module(_entry_with_http_call(), "example.com", ctx)
    assert result.contacts == []


def test_contact_asdict_round_trips_through_json():
    import json

    event = ContactEvent(timestamp="t", module="m", kind="http", destination="d")
    assert json.loads(json.dumps(contact_asdict(event)))["module"] == "m"
