from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from robinshood.core.cache import CacheStats
from robinshood.core.egress import EgressLog
from robinshood.core.shell import run_command

INPUT_TYPES = frozenset({"domain", "ip", "email", "username", "url", "phone"})


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    category: str
    description: str
    consumes: str
    produces: tuple[str, ...]
    requires_key: tuple[str, ...] = ()
    requires_bin: tuple[str, ...] = ()
    passive: bool = True
    source_url: str = ""
    # Read/write budget for this module's HTTP traffic, when the default is too
    # tight for a known-slow source. Applied by the *caller* when it builds the
    # client — modules never pass a timeout to ctx.http themselves.
    http_timeout: float | None = None

    def __post_init__(self) -> None:
        if self.consumes not in INPUT_TYPES:
            raise ValueError(
                f"module {self.name!r}: consumes={self.consumes!r} is not one of {sorted(INPUT_TYPES)}"
            )
        if not self.produces:
            raise ValueError(f"module {self.name!r}: produces must be non-empty")


@dataclass(frozen=True)
class Finding:
    type: str
    value: str
    module: str
    target: str
    source_url: str = ""
    raw: dict | None = None
    confidence: str = "Probable"
    timestamp: str = field(default_factory=utc_now)


@dataclass
class ModuleResult:
    module: str
    target: str
    ok: bool
    started_at: str
    finished_at: str
    duration_ms: float
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    # How much of this run was replayed from cache rather than fetched live.
    cached_responses: int = 0
    max_cache_age_s: float | None = None
    # Receipts of what this run actually put on the wire (or, for CLI-wrapper
    # modules, which binary it invoked). Empty when egress logging isn't wired
    # up for this call site.
    contacts: list = field(default_factory=list)


@dataclass
class RunContext:
    http: httpx.Client
    env: dict
    timeout: float = 15.0
    # Modules shell out through this, never subprocess directly — tests swap in
    # a fake so the suite never depends on a CLI tool being installed.
    exec: Callable[..., str] = run_command
    # Set only when the response cache is enabled. Read by the runner, never by
    # a module — it exists so evidence.jsonl can say whether a run came off disk.
    cache_stats: CacheStats | None = None
    # Receipts of every outbound contact this run actually made. Populated by
    # EgressLoggingTransport/logged_exec, read by the runner — a module never
    # touches this directly, same as cache_stats.
    egress_log: EgressLog | None = None
