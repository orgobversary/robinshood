from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import httpx

from robinshood.core.cache import CacheStats, CachingTransport
from robinshood.core.egress import EgressLog, EgressLoggingTransport

USER_AGENT = "robinshood/0.1 (+https://github.com/)"

# A dead host should fail fast; a slow-but-alive API should get the full read
# budget. One flat timeout for both meant crt.sh — routinely >15s — was recorded
# as a *failure* rather than a slow success.
CONNECT_TIMEOUT = 5.0

# Transient, retry-worthy. A persistent 500 is a real server-side failure and
# burning attempts on it just delays an accurate error.
RETRY_STATUS = frozenset({429, 502, 503, 504})

# Only methods with no side effects. Every robinshood module uses GET, but the
# transport must not silently re-send a hypothetical POST.
RETRY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

DEFAULT_ATTEMPTS = 3
DEFAULT_BACKOFF = 0.5
MAX_BACKOFF = 10.0
# Ceiling on delay this transport will add to one request, so a sweep can't
# stall for minutes behind one rate-limited source.
MAX_TOTAL_DELAY = 20.0

# Bounded so a sweep's worker pool has a defined ceiling rather than httpx's
# default of 100 connections.
DEFAULT_LIMITS = httpx.Limits(max_connections=20, max_keepalive_connections=10)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Honors the integer-seconds form of Retry-After. The HTTP-date form is
    deliberately not parsed — it falls through to normal backoff rather than
    risking a misparse into a very long sleep."""
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        value = float(raw.strip())
    except ValueError:
        return None
    return value if value >= 0 else None


class RetryTransport(httpx.BaseTransport):
    """Retries transient failures with exponential backoff.

    Wraps another transport rather than living in the modules: a module calls
    `ctx.http.get(...)` and knows nothing about retries, the same way it knows
    nothing about the proxy (AGENTS.md, "Invariants").

    `sleep` is injectable so tests can assert backoff without waiting.
    """

    def __init__(
        self,
        inner: httpx.BaseTransport,
        max_attempts: int = DEFAULT_ATTEMPTS,
        backoff: float = DEFAULT_BACKOFF,
        max_total_delay: float = MAX_TOTAL_DELAY,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._inner = inner
        self._max_attempts = max(1, max_attempts)
        self._backoff = backoff
        self._max_total_delay = max_total_delay
        self._sleep = sleep

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method not in RETRY_METHODS:
            return self._inner.handle_request(request)

        spent = 0.0
        for attempt in range(1, self._max_attempts + 1):
            last = attempt == self._max_attempts
            try:
                response = self._inner.handle_request(request)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                # Connect-level only. A read timeout means the server accepted
                # us and is just slow — retrying re-does the slow work and
                # hammers a source that is already struggling.
                if last:
                    raise
                delay = self._delay(attempt, None)
                if spent + delay > self._max_total_delay:
                    raise
                spent += delay
                self._sleep(delay)
                continue

            if response.status_code not in RETRY_STATUS or last:
                return response

            delay = self._delay(attempt, response)
            if spent + delay > self._max_total_delay:
                return response
            # The body must be drained before the connection can be reused.
            response.read()
            response.close()
            spent += delay
            self._sleep(delay)

        raise AssertionError("unreachable: loop always returns or raises")  # pragma: no cover

    def _delay(self, attempt: int, response: httpx.Response | None) -> float:
        if response is not None:
            retry_after = _retry_after_seconds(response)
            if retry_after is not None:
                return min(retry_after, self._max_total_delay)
        return min(self._backoff * (2 ** (attempt - 1)), MAX_BACKOFF)

    def close(self) -> None:
        self._inner.close()


def build_client(
    timeout: float = 15.0,
    proxy: str | None = None,
    user_agent: str | None = None,
    cache_dir: Path | None = None,
    cache_ttl: float = 0.0,
    cache_stats: CacheStats | None = None,
    egress_log: EgressLog | None = None,
) -> httpx.Client:
    """The single place every HTTP module's traffic passes through. `proxy`
    accepts an http(s):// or socks5(h):// URL — SOCKS5 needs the `socksio`
    package (pulled in via the `httpx[socks]` dependency).

    `timeout` is the read/write budget; connecting is held to CONNECT_TIMEOUT
    regardless, so an unreachable host fails in seconds instead of burning a
    slow module's whole 60s allowance.

    `cache_ttl` of 0 (the default) disables caching entirely. When enabled, the
    cache wraps *outside* the retry layer so a hit short-circuits before any
    retry logic runs."""
    resolved_user_agent = user_agent or USER_AGENT
    inner: httpx.BaseTransport = httpx.HTTPTransport(proxy=proxy, limits=DEFAULT_LIMITS)
    if egress_log is not None:
        # Innermost, before retry, so every actual attempt gets its own
        # receipt — including each retry, which really did go out again.
        inner = EgressLoggingTransport(inner, egress_log, proxy, resolved_user_agent)
    transport: httpx.BaseTransport = RetryTransport(inner)
    if cache_ttl > 0 and cache_dir is not None:
        # Outermost: a cache hit must never reach the logging transport,
        # since nothing actually left the machine for that request.
        transport = CachingTransport(transport, cache_dir, cache_ttl, stats=cache_stats)
    return httpx.Client(
        headers={"User-Agent": resolved_user_agent},
        timeout=httpx.Timeout(
            connect=CONNECT_TIMEOUT, read=timeout, write=timeout, pool=timeout
        ),
        follow_redirects=True,
        transport=transport,
    )
