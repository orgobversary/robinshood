from __future__ import annotations

import httpx
import pytest

from robinshood.core.http import (
    CONNECT_TIMEOUT,
    MAX_TOTAL_DELAY,
    RetryTransport,
    build_client,
)


class _Recorder:
    """Collects the delays a retry would have slept, so the suite asserts
    backoff without ever waiting."""

    def __init__(self):
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def _client(handler, sleep, **kwargs) -> httpx.Client:
    return httpx.Client(transport=RetryTransport(httpx.MockTransport(handler), sleep=sleep, **kwargs))


def _sequence(responses):
    """Serves each response in turn, recording how many times it was called."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        item = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(item, Exception):
            raise item
        return item

    return handler, calls


def test_retries_transient_status_then_succeeds():
    handler, calls = _sequence([httpx.Response(503), httpx.Response(200, json={"ok": True})])
    sleep = _Recorder()
    with _client(handler, sleep) as client:
        resp = client.get("https://example.com/")
    assert resp.status_code == 200
    assert len(calls) == 2
    assert sleep.delays == [0.5]


def test_persistent_500_is_not_retried():
    """A 500 is a real server-side failure, not a transient one — burning
    attempts on it only delays an accurate error."""
    handler, calls = _sequence([httpx.Response(500)])
    sleep = _Recorder()
    with _client(handler, sleep) as client:
        resp = client.get("https://example.com/")
    assert resp.status_code == 500
    assert len(calls) == 1
    assert sleep.delays == []


def test_attempts_are_capped_and_last_response_returned():
    handler, calls = _sequence([httpx.Response(503)])
    sleep = _Recorder()
    with _client(handler, sleep, max_attempts=3) as client:
        resp = client.get("https://example.com/")
    assert resp.status_code == 503
    assert len(calls) == 3
    assert sleep.delays == [0.5, 1.0]  # exponential, and none after the final attempt


def test_retry_after_header_is_honored():
    handler, _ = _sequence([httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200)])
    sleep = _Recorder()
    with _client(handler, sleep) as client:
        assert client.get("https://example.com/").status_code == 200
    assert sleep.delays == [7.0]


def test_unparseable_retry_after_falls_back_to_backoff():
    """An HTTP-date Retry-After is not parsed — misparsing it into a very long
    sleep is worse than plain backoff."""
    handler, _ = _sequence(
        [httpx.Response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}), httpx.Response(200)]
    )
    sleep = _Recorder()
    with _client(handler, sleep) as client:
        assert client.get("https://example.com/").status_code == 200
    assert sleep.delays == [0.5]


def test_absurd_retry_after_is_clamped_to_the_total_budget():
    handler, _ = _sequence([httpx.Response(429, headers={"Retry-After": "9999"}), httpx.Response(200)])
    sleep = _Recorder()
    with _client(handler, sleep) as client:
        client.get("https://example.com/")
    assert all(d <= MAX_TOTAL_DELAY for d in sleep.delays)


def test_connect_errors_are_retried():
    handler, calls = _sequence(
        [httpx.ConnectError("refused"), httpx.ConnectError("refused"), httpx.Response(200)]
    )
    sleep = _Recorder()
    with _client(handler, sleep) as client:
        assert client.get("https://example.com/").status_code == 200
    assert len(calls) == 3


def test_read_timeout_is_not_retried():
    """The server accepted us and is merely slow; retrying redoes the slow work
    and hammers a source that is already struggling."""
    handler, calls = _sequence([httpx.ReadTimeout("slow")])
    sleep = _Recorder()
    with _client(handler, sleep) as client, pytest.raises(httpx.ReadTimeout):
        client.get("https://example.com/")
    assert len(calls) == 1


def test_non_idempotent_methods_are_never_retried():
    handler, calls = _sequence([httpx.Response(503)])
    sleep = _Recorder()
    with _client(handler, sleep) as client:
        assert client.post("https://example.com/", json={}).status_code == 503
    assert len(calls) == 1


def test_build_client_splits_connect_from_read_timeout():
    with build_client(timeout=60.0) as client:
        assert client.timeout.connect == CONNECT_TIMEOUT
        assert client.timeout.read == 60.0
        assert isinstance(client._transport, RetryTransport)


def test_build_client_still_accepts_a_proxy():
    """Proxying moved to the transport layer; the call sites in cli.py and
    tui/app.py must keep working unchanged."""
    with build_client(proxy="socks5://127.0.0.1:9050", user_agent="x/1") as client:
        assert client.headers["User-Agent"] == "x/1"
