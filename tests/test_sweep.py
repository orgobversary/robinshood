from __future__ import annotations

import contextlib
import threading
import time

import httpx
import pytest

from robinshood.core.registry import RegisteredModule, Registry
from robinshood.core.sweep import (
    SweepError,
    missing_requirements,
    run_sweep,
    select_modules,
)
from robinshood.core.types import Finding, ModuleSpec, RunContext


def _entry(name, consumes="ip", *, keys=(), bins=(), passive=True, delay=0.0, boom=False):
    spec = ModuleSpec(
        name=name,
        category="test",
        description=f"{name} description",
        consumes=consumes,
        produces=("ip",),
        requires_key=tuple(keys),
        requires_bin=tuple(bins),
        passive=passive,
    )

    def run(target, ctx):
        if delay:
            time.sleep(delay)
        if boom:
            raise RuntimeError("module exploded")
        return [Finding(type="ip", value=f"{name}-value", module=name, target=target)]

    return RegisteredModule(spec=spec, run=run)


def _registry(*entries):
    return Registry({e.spec.name: e for e in entries})


@contextlib.contextmanager
def _ctx(entry):
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))) as c:
        yield RunContext(http=c, env={})


# ── selection ────────────────────────────────────────────────────────────


def test_selects_only_modules_consuming_the_target_type():
    registry = _registry(_entry("ip_one", "ip"), _entry("dom_one", "domain"))
    runnable, skipped = select_modules(registry, "8.8.8.8", {})
    assert [e.spec.name for e in runnable] == ["ip_one"]
    assert skipped == []


def test_unavailable_modules_are_skipped_not_run():
    """Running them would write guaranteed failures into evidence.jsonl every
    sweep, burying the real ones."""
    registry = _registry(_entry("free"), _entry("needs_key", keys=("NOPE_API_KEY",)))
    runnable, skipped = select_modules(registry, "8.8.8.8", {})
    assert [e.spec.name for e in runnable] == ["free"]
    assert [(e.spec.name, m) for e, m in skipped] == [("needs_key", ["NOPE_API_KEY"])]


def test_present_key_makes_a_module_runnable():
    registry = _registry(_entry("needs_key", keys=("SOME_API_KEY",)))
    runnable, skipped = select_modules(registry, "8.8.8.8", {"SOME_API_KEY": "x"})
    assert [e.spec.name for e in runnable] == ["needs_key"]
    assert skipped == []


def test_include_unavailable_runs_them_anyway():
    registry = _registry(_entry("needs_key", keys=("NOPE_API_KEY",)))
    runnable, skipped = select_modules(registry, "8.8.8.8", {}, include_unavailable=True)
    assert [e.spec.name for e in runnable] == ["needs_key"]
    assert skipped == []


def test_missing_binary_is_reported():
    entry = _entry("needs_bin", bins=("definitely-not-a-real-binary-xyz",))
    assert missing_requirements(entry, {}) == ["definitely-not-a-real-binary-xyz"]


def test_undetectable_target_is_an_actionable_error():
    with pytest.raises(SweepError, match="could not tell what kind of target"):
        select_modules(_registry(_entry("a")), "!!! not a target !!!", {})


def test_selection_is_sorted_by_module_name():
    registry = _registry(_entry("zulu"), _entry("alpha"), _entry("mike"))
    runnable, _ = select_modules(registry, "8.8.8.8", {})
    assert [e.spec.name for e in runnable] == ["alpha", "mike", "zulu"]


# ── execution ────────────────────────────────────────────────────────────


def test_results_are_sorted_by_module_not_completion_order():
    """This is what keeps findings.jsonl — and the exported note — identical
    across sweeps regardless of which module happens to finish first."""
    entries = [_entry("zulu", delay=0.0), _entry("alpha", delay=0.15)]
    results = run_sweep(entries, "8.8.8.8", _ctx)
    assert [r.module for r in results] == ["alpha", "zulu"]


def test_modules_actually_run_concurrently():
    entries = [_entry(f"m{i}", delay=0.2) for i in range(4)]
    started = time.perf_counter()
    results = run_sweep(entries, "8.8.8.8", _ctx, max_workers=4)
    elapsed = time.perf_counter() - started
    assert len(results) == 4
    # Serial would be ~0.8s; concurrent should land near the slowest single one.
    assert elapsed < 0.6


def test_max_workers_bounds_concurrency():
    live = 0
    peak = 0
    lock = threading.Lock()

    def tracked(name):
        entry = _entry(name)

        def run(target, ctx):
            nonlocal live, peak
            with lock:
                live += 1
                peak = max(peak, live)
            time.sleep(0.05)
            with lock:
                live -= 1
            return []

        return RegisteredModule(spec=entry.spec, run=run)

    run_sweep([tracked(f"m{i}") for i in range(6)], "8.8.8.8", _ctx, max_workers=2)
    assert peak <= 2


def test_one_module_failing_never_aborts_the_sweep():
    entries = [_entry("good"), _entry("bad", boom=True)]
    results = run_sweep(entries, "8.8.8.8", _ctx)
    assert [(r.module, r.ok) for r in results] == [("bad", False), ("good", True)]
    assert "module exploded" in dict((r.module, r.error) for r in results)["bad"]


def test_on_result_fires_once_per_module():
    seen = []
    entries = [_entry("a"), _entry("b"), _entry("c")]
    run_sweep(entries, "8.8.8.8", _ctx, on_result=seen.append)
    assert sorted(r.module for r in seen) == ["a", "b", "c"]


def test_empty_selection_is_an_empty_sweep_not_a_crash():
    assert run_sweep([], "8.8.8.8", _ctx) == []


def test_each_module_gets_its_own_context():
    """Per-module clients are what let http_timeout and CacheStats be per-module
    rather than shared and racing."""
    # Keeps every ctx alive for the assertion below -- id() on an object that
    # gets garbage-collected as soon as the `with` block exits is not a
    # reliable identity check, since CPython can (and does) reuse the freed
    # address for the very next allocation.
    seen = []

    @contextlib.contextmanager
    def tracking_ctx(entry):
        with _ctx(entry) as ctx:
            seen.append(ctx)
            yield ctx

    run_sweep([_entry("a"), _entry("b")], "8.8.8.8", tracking_ctx)
    assert len({id(ctx) for ctx in seen}) == 2
