from __future__ import annotations

import json
import time

import httpx

from robinshood.core.cache import CacheStats, CachingTransport, cache_key
from robinshood.core.case import Case
from robinshood.core.registry import RegisteredModule
from robinshood.core.runner import run_module
from robinshood.core.types import Finding, ModuleSpec, RunContext


def _counting_transport(status=200, body=None):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(status, json=body if body is not None else {"n": len(calls)})

    return httpx.MockTransport(handler), calls


def _client(tmp_path, ttl, stats=None, **kw):
    inner, calls = _counting_transport(**kw)
    transport = CachingTransport(inner, tmp_path / "cache", ttl, stats=stats)
    return httpx.Client(transport=transport), calls, transport


def test_second_identical_get_never_reaches_the_network(tmp_path):
    client, calls, transport = _client(tmp_path, ttl=3600)
    with client:
        first = client.get("https://example.com/a").json()
        second = client.get("https://example.com/a").json()
    assert first == second
    assert len(calls) == 1
    assert transport.stats.hits == 1
    assert transport.stats.misses == 1


def test_expired_entry_goes_back_to_the_network(tmp_path):
    client, calls, _ = _client(tmp_path, ttl=3600)
    with client:
        client.get("https://example.com/a")
    # Age the stored entry past any plausible TTL.
    entry_path = next((tmp_path / "cache").glob("*.json"))
    entry = json.loads(entry_path.read_text())
    entry["stored_at"] = time.time() - 10_000
    entry_path.write_text(json.dumps(entry))

    client2, calls2, _ = _client(tmp_path, ttl=60)
    with client2:
        client2.get("https://example.com/a")
    assert len(calls2) == 1  # a miss, not a replay


def test_ttl_zero_disables_caching_entirely(tmp_path):
    client, calls, _ = _client(tmp_path, ttl=0)
    with client:
        client.get("https://example.com/a")
        client.get("https://example.com/a")
    assert len(calls) == 2
    assert not (tmp_path / "cache").exists()


def test_non_200_responses_are_never_stored(tmp_path):
    """A 404 or a 500 is a fact about a moment, not a durable one."""
    client, calls, _ = _client(tmp_path, ttl=3600, status=404)
    with client:
        client.get("https://example.com/missing")
        client.get("https://example.com/missing")
    assert len(calls) == 2


def test_post_is_never_cached(tmp_path):
    client, calls, _ = _client(tmp_path, ttl=3600)
    with client:
        client.post("https://example.com/a", json={})
        client.post("https://example.com/a", json={})
    assert len(calls) == 2


def test_query_parameter_order_is_one_entry_not_two(tmp_path):
    client, calls, _ = _client(tmp_path, ttl=3600)
    with client:
        client.get("https://example.com/r?name=x&type=A")
        client.get("https://example.com/r?type=A&name=x")
    assert len(calls) == 1


def test_different_queries_are_different_entries(tmp_path):
    client, calls, _ = _client(tmp_path, ttl=3600)
    with client:
        client.get("https://example.com/r?type=A")
        client.get("https://example.com/r?type=AAAA")
    assert len(calls) == 2


def test_corrupt_entry_is_a_miss_not_an_error(tmp_path):
    """The cache is an optimization; a hand-edited or torn entry must never
    break a run."""
    client, calls, _ = _client(tmp_path, ttl=3600)
    with client:
        client.get("https://example.com/a")
    next((tmp_path / "cache").glob("*.json")).write_text("{not json")

    client2, calls2, _ = _client(tmp_path, ttl=3600)
    with client2:
        assert client2.get("https://example.com/a").status_code == 200
    assert len(calls2) == 1


def test_cache_key_ignores_parameter_order():
    a = httpx.Request("GET", "https://x.test/p?b=2&a=1")
    b = httpx.Request("GET", "https://x.test/p?a=1&b=2")
    assert cache_key(a) == cache_key(b)


def _module_entry():
    spec = ModuleSpec(
        name="fake", category="test", description="", consumes="domain", produces=("ip",)
    )

    def run(target, ctx):
        ctx.http.get("https://example.com/a")
        return [Finding(type="ip", value="1.1.1.1", module="fake", target=target)]

    return RegisteredModule(spec=spec, run=run)


def test_cached_run_is_marked_in_the_evidence_log(tmp_path):
    """evidence.jsonl must never present a replayed response as a live lookup."""
    stats = CacheStats()
    client, _, _ = _client(tmp_path, ttl=3600, stats=stats)
    entry = _module_entry()
    case = Case.open(tmp_path / "cases", "example.com")

    with client:
        ctx = RunContext(http=client, env={}, cache_stats=stats)
        live = run_module(entry, "example.com", ctx)
        case.record_result(live)
        replayed = run_module(entry, "example.com", ctx)
        case.record_result(replayed)

    assert live.cached_responses == 0
    assert replayed.cached_responses == 1

    rows = case.load_evidence()
    assert rows[0]["cached"] is False
    assert rows[1]["cached"] is True
    assert rows[1]["cached_responses"] == 1
    assert rows[1]["max_cache_age_s"] is not None


def test_cache_stats_absent_means_no_cache_claims(tmp_path):
    """With the cache off (the default), every run reports as live."""
    inner, _ = _counting_transport()
    with httpx.Client(transport=inner) as client:
        result = run_module(_module_entry(), "example.com", RunContext(http=client, env={}))
    assert result.cached_responses == 0
    assert result.max_cache_age_s is None
