from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from robinshood.core.cache import CacheStats
from robinshood.core.egress import EgressLog
from robinshood.core.shell import run_command

INPUT_TYPES = frozenset({"domain", "ip", "email", "username", "url", "phone"})
OPTION_KINDS = frozenset({"bool", "int", "str", "choice", "choice_list"})


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ModuleOption:
    """One typed, auditable control exposed by a module.

    Modules translate these values into upstream API parameters or argv
    elements. Robinshood deliberately does not accept arbitrary raw flags.
    """

    name: str
    description: str
    kind: str = "str"
    default: Any = None
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").isalnum():
            raise ValueError(f"invalid module option name {self.name!r}")
        if self.kind not in OPTION_KINDS:
            raise ValueError(
                f"option {self.name!r}: kind must be one of {sorted(OPTION_KINDS)}"
            )
        if self.kind in {"choice", "choice_list"} and not self.choices:
            raise ValueError(f"option {self.name!r}: {self.kind} requires choices")
        if self.kind not in {"choice", "choice_list"} and self.choices:
            raise ValueError(f"option {self.name!r}: choices only apply to choice options")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError(f"option {self.name!r}: minimum exceeds maximum")
        if self.default is None:
            return
        if self.kind == "bool" and not isinstance(self.default, bool):
            raise ValueError(f"option {self.name!r}: default must be a bool")
        if self.kind == "int":
            if not isinstance(self.default, int) or isinstance(self.default, bool):
                raise ValueError(f"option {self.name!r}: default must be an integer")
            if self.minimum is not None and self.default < self.minimum:
                raise ValueError(f"option {self.name!r}: default is below minimum")
            if self.maximum is not None and self.default > self.maximum:
                raise ValueError(f"option {self.name!r}: default exceeds maximum")
        if self.kind == "str" and not isinstance(self.default, str):
            raise ValueError(f"option {self.name!r}: default must be a string")
        if self.kind == "choice" and self.default not in self.choices:
            raise ValueError(f"option {self.name!r}: default must be one of its choices")
        if self.kind == "choice_list":
            if not isinstance(self.default, tuple):
                raise ValueError(f"option {self.name!r}: default must be a tuple")
            if any(value not in self.choices for value in self.default):
                raise ValueError(f"option {self.name!r}: default contains an invalid choice")


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
    options: tuple[ModuleOption, ...] = ()
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
        option_names = [option.name for option in self.options]
        if len(option_names) != len(set(option_names)):
            raise ValueError(f"module {self.name!r}: option names must be unique")


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
    options: dict[str, Any] = field(default_factory=dict)
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
    options: dict[str, Any] = field(default_factory=dict)
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

    def option(self, name: str, default: Any = None) -> Any:
        """Read a validated module option, with a fallback for direct unit tests."""
        return self.options.get(name, default)
