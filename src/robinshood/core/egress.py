from __future__ import annotations

import datetime as dt
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Callable

import httpx


# Duplicated from core/types.py rather than imported, to avoid a circular
# import: types.py needs EgressLog for RunContext's type hint, and this is a
# one-line format shared by both, same precedent as core/cache.py's CacheStats
# not depending on types.py either.
def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Query-parameter names that carry secrets. numlookup_phone sends its API key
# as ?apikey=... (HIBP's goes in a header, which this module never logs at
# all) — a forensic receipt that leaks the key defeats its own purpose.
_SECRET_PARAM_NAMES = {"apikey", "api_key", "key", "token", "auth", "password", "secret"}


def _redact_url(url: httpx.URL) -> str:
    query = urllib.parse.parse_qsl(url.query.decode(), keep_blank_values=True)
    redacted = [
        (name, "REDACTED" if name.lower() in _SECRET_PARAM_NAMES else value)
        for name, value in query
    ]
    clean = url.copy_with(query=urllib.parse.urlencode(redacted).encode() or None)
    return str(clean)


@dataclass(frozen=True)
class ContactEvent:
    """One outbound point of contact — a receipt of what robinshood actually
    put on the wire, from the outside looking in. Never records header
    contents (where every module's API key actually lives), only what a
    passive observer of the connection itself could have seen."""

    timestamp: str
    module: str
    kind: str  # "http" or "cli"
    destination: str  # redacted URL for http, binary name for cli
    proxy: str | None = None
    user_agent: str | None = None
    tor_rotated: bool = False
    status: str = "ok"  # "ok", "error", or an HTTP status code as a string
    error: str | None = None


class EgressLog:
    """Shared, mutable sink for ContactEvents — one instance per RunContext,
    same pattern as CacheStats.

    `current_module` exists because a single httpx.Client (and so a single
    EgressLoggingTransport) can outlive many separate module runs — the TUI
    builds one client at startup and reuses it for every module the user
    selects in that session. The caller sets it immediately before each
    run_module() call; the transport reads it at request time rather than
    baking a module name in at construction time.
    """

    def __init__(self) -> None:
        self.events: list[ContactEvent] = []
        self.current_module: str = ""
        # Also mutable, not a fixed constructor arg on the transport: the TUI's
        # single Tor-rotate checkbox varies per run on a client that outlives
        # every run, same reason current_module works this way.
        self.current_tor_rotated: bool = False

    def record(self, event: ContactEvent) -> None:
        self.events.append(event)


class EgressLoggingTransport(httpx.BaseTransport):
    """Wraps the innermost transport (before retry) so every actual attempt —
    including each retry — gets its own receipt. A cache hit never reaches
    this far, which is correct: nothing left the machine, so there is nothing
    to log. Composition: CachingTransport(RetryTransport(EgressLoggingTransport(
    HTTPTransport)))."""

    def __init__(
        self,
        inner: httpx.BaseTransport,
        log: EgressLog,
        proxy: str | None,
        user_agent: str | None,
    ):
        self._inner = inner
        self._log = log
        self._proxy = proxy
        self._user_agent = user_agent

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            response = self._inner.handle_request(request)
        except Exception as exc:  # noqa: BLE001 - a failed attempt is still a receipt, re-raised after logging
            self._log.record(
                ContactEvent(
                    timestamp=utc_now(),
                    module=self._log.current_module,
                    kind="http",
                    destination=_redact_url(request.url),
                    proxy=self._proxy,
                    user_agent=self._user_agent,
                    tor_rotated=self._log.current_tor_rotated,
                    status="error",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            raise
        self._log.record(
            ContactEvent(
                timestamp=utc_now(),
                module=self._log.current_module,
                kind="http",
                destination=_redact_url(request.url),
                proxy=self._proxy,
                user_agent=self._user_agent,
                tor_rotated=self._log.current_tor_rotated,
                status=str(response.status_code),
            )
        )
        return response

    def close(self) -> None:
        self._inner.close()


def logged_exec(
    exec_fn: Callable[..., str],
    log: EgressLog,
    proxy: str | None,
) -> Callable[..., str]:
    """Wraps ctx.exec the same way EgressLoggingTransport wraps ctx.http.
    robinshood cannot see what a CLI tool contacts internally — subfinder's
    own HTTP calls happen inside its own process — so this can only honestly
    record that the binary was invoked, not each of its own contacts."""

    def wrapped(argv: list[str], timeout: float | None = None, cwd: str | None = None) -> str:
        try:
            result = exec_fn(argv, timeout=timeout, cwd=cwd)
        except Exception as exc:  # noqa: BLE001 - logged, then re-raised unchanged
            log.record(
                ContactEvent(
                    timestamp=utc_now(),
                    module=log.current_module,
                    kind="cli",
                    destination=argv[0],
                    proxy=proxy,
                    tor_rotated=log.current_tor_rotated,
                    status="error",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            raise
        log.record(
            ContactEvent(
                timestamp=utc_now(), module=log.current_module, kind="cli", destination=argv[0],
                proxy=proxy, tor_rotated=log.current_tor_rotated, status="ok",
            )
        )
        return result

    return wrapped


def contact_asdict(event: ContactEvent) -> dict:
    return asdict(event)
