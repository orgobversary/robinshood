from __future__ import annotations

import time
from dataclasses import replace

from robinshood.core.options import effective_module_options, jsonable_options
from robinshood.core.registry import RegisteredModule
from robinshood.core.types import ModuleResult, RunContext, utc_now


def run_module(entry: RegisteredModule, target: str, ctx: RunContext) -> ModuleResult:
    """Executes one module's run(), owning timing, timeout, and error capture
    so individual module files stay small and never need their own
    try/except-everything boilerplate."""
    started_at = utc_now()
    t0 = time.monotonic()
    error: str | None = None
    findings = []
    # Snapshot before/after rather than reading absolutes: one client (and so
    # one stats object) may be shared across several modules in a sweep.
    hits_before = ctx.cache_stats.hits if ctx.cache_stats else 0
    ages_before = len(ctx.cache_stats.ages) if ctx.cache_stats else 0
    contacts_before = len(ctx.egress_log.events) if ctx.egress_log else 0
    if ctx.egress_log is not None:
        # The transport reads this at request time, not at RunContext-
        # construction time — needed because one client (and one egress log)
        # can outlive many separate run_module() calls in the TUI.
        ctx.egress_log.current_module = entry.spec.name
    effective_options = effective_module_options(entry.spec, ctx.options)
    module_ctx = replace(ctx, options=effective_options)
    try:
        if entry.validate_options is not None:
            entry.validate_options(effective_options)
        findings = entry.run(target, module_ctx)
    except Exception as exc:  # noqa: BLE001 - module failures must never crash the runner
        error = f"{type(exc).__name__}: {exc}"
    duration_ms = (time.monotonic() - t0) * 1000
    finished_at = utc_now()

    cached_responses = 0
    max_cache_age_s = None
    if ctx.cache_stats is not None:
        cached_responses = ctx.cache_stats.hits - hits_before
        ages = ctx.cache_stats.ages[ages_before:]
        max_cache_age_s = max(ages) if ages else None

    contacts = ctx.egress_log.events[contacts_before:] if ctx.egress_log else []

    return ModuleResult(
        module=entry.spec.name,
        target=target,
        ok=error is None,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        findings=findings,
        error=error,
        options=jsonable_options(effective_options),
        cached_responses=cached_responses,
        max_cache_age_s=max_cache_age_s,
        contacts=contacts,
    )
