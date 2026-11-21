from __future__ import annotations

import concurrent.futures
import shutil
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager

from robinshood.core.detect import detect_target_type
from robinshood.core.registry import RegisteredModule, Registry
from robinshood.core.runner import run_module
from robinshood.core.types import ModuleResult, RunContext

# Modules are I/O-bound (one HTTP call or one subprocess each), so threads are
# the right tool — and a bounded pool keeps a sweep from opening one connection
# per module against a shared connection limit.
DEFAULT_MAX_WORKERS = 8

CtxFactory = Callable[[RegisteredModule], AbstractContextManager[RunContext]]


class SweepError(Exception):
    """Raised for conditions the user needs to act on, not bugs."""


def missing_requirements(entry: RegisteredModule, env: dict) -> list[str]:
    """What this module needs but doesn't have — env vars first, then binaries."""
    missing = [key for key in entry.spec.requires_key if not env.get(key)]
    missing += [binary for binary in entry.spec.requires_bin if shutil.which(binary) is None]
    return missing


def select_modules(
    registry: Registry,
    target: str,
    env: dict,
    include_unavailable: bool = False,
) -> tuple[list[RegisteredModule], list[tuple[RegisteredModule, list[str]]]]:
    """Every module that consumes this target's type, split into runnable and
    skipped-for-missing-requirements.

    Filtering unavailable modules is not cosmetic: without it a sweep writes a
    handful of guaranteed failures into evidence.jsonl every time, which buries
    real failures in noise. `include_unavailable` runs them anyway, so the
    resulting error is on the record when that's what you want.
    """
    target_type = detect_target_type(target)
    if target_type is None:
        raise SweepError(
            f"could not tell what kind of target {target!r} is — "
            f"expected a domain, ip, email, username, or url"
        )

    candidates = sorted(registry.consuming(target_type), key=lambda e: e.spec.name)
    if include_unavailable:
        return candidates, []

    runnable: list[RegisteredModule] = []
    skipped: list[tuple[RegisteredModule, list[str]]] = []
    for entry in candidates:
        missing = missing_requirements(entry, env)
        if missing:
            skipped.append((entry, missing))
        else:
            runnable.append(entry)
    return runnable, skipped


def run_sweep(
    entries: Iterable[RegisteredModule],
    target: str,
    ctx_factory: CtxFactory,
    max_workers: int | None = None,
    on_result: Callable[[ModuleResult], None] | None = None,
) -> list[ModuleResult]:
    """Runs every module against one target concurrently.

    Each worker builds its own RunContext through `ctx_factory` — so a module's
    `http_timeout` applies to its own client, and each gets its own CacheStats
    rather than racing on a shared one.

    **Results come back sorted by module name, never in completion order.** The
    caller records them in that order, which is what keeps findings.jsonl — and
    therefore the exported note — byte-identical across runs (AGENTS.md,
    "Rendering must stay deterministic"). `on_result` fires as each future
    lands, for live progress; display order may vary, recording order never does.
    """
    entries = list(entries)
    if not entries:
        return []

    workers = max_workers or min(DEFAULT_MAX_WORKERS, len(entries))
    results: list[ModuleResult] = []

    def _one(entry: RegisteredModule) -> ModuleResult:
        with ctx_factory(entry) as ctx:
            return run_module(entry, target, ctx)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_one, entry): entry for entry in entries}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if on_result is not None:
                on_result(result)

    results.sort(key=lambda r: r.module)
    return results
