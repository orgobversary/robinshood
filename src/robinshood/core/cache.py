from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import httpx

# Only responses that are safe to replay. A POST is never cached, and a non-200
# is never stored — a 404 or a 500 is a fact about a moment, not a durable one.
CACHEABLE_METHODS = frozenset({"GET"})
CACHEABLE_STATUS = frozenset({200})

# Stripped before replay: the stored body is already decoded, so replaying the
# original encoding headers would make httpx try to decode it a second time.
_DROP_HEADERS = frozenset({"content-encoding", "content-length", "transfer-encoding"})


@dataclass
class CacheStats:
    """Mutable, shared with the transport so the runner can report — honestly —
    how much of a run came off disk instead of the network."""

    hits: int = 0
    misses: int = 0
    ages: list[float] = field(default_factory=list)

    @property
    def max_age_s(self) -> float | None:
        return max(self.ages) if self.ages else None


def cache_key(request: httpx.Request) -> str:
    """Query parameters are sorted so the same lookup expressed in a different
    parameter order is one cache entry, not two."""
    url = request.url
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(url.query.decode())))
    canonical = f"{request.method} {url.scheme}://{url.host}{url.path}?{query}"
    return hashlib.sha256(canonical.encode()).hexdigest()


class CachingTransport(httpx.BaseTransport):
    """Replays previously-seen GET responses from disk.

    Entries are plain JSON files, deletable by hand — the same philosophy as the
    JSONL case store. Sits *outside* RetryTransport so a hit short-circuits
    before any retry logic runs.

    Opt-in: a ttl of 0 disables it entirely, which is the default everywhere.
    """

    def __init__(
        self,
        inner: httpx.BaseTransport,
        cache_dir: Path,
        ttl: float,
        stats: CacheStats | None = None,
    ):
        self._inner = inner
        self._dir = Path(cache_dir)
        self._ttl = ttl
        self.stats = stats if stats is not None else CacheStats()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self._ttl <= 0 or request.method not in CACHEABLE_METHODS:
            return self._inner.handle_request(request)

        path = self._dir / f"{cache_key(request)}.json"
        cached = self._load(path)
        if cached is not None:
            entry, age = cached
            self.stats.hits += 1
            self.stats.ages.append(age)
            return httpx.Response(
                entry["status"],
                headers=entry["headers"],
                content=base64.b64decode(entry["body"]),
                request=request,
            )

        self.stats.misses += 1
        response = self._inner.handle_request(request)
        if response.status_code not in CACHEABLE_STATUS:
            return response

        body = response.read()
        self._store(path, response, body)
        # The body was consumed to store it, so hand back a fresh response
        # rather than one the caller can no longer read.
        return httpx.Response(
            response.status_code,
            headers=self._replayable_headers(response),
            content=body,
            request=request,
        )

    def _load(self, path: Path) -> tuple[dict, float] | None:
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A truncated or hand-edited entry is a miss, never an error — the
            # cache is an optimization and must never break a run.
            return None
        age = time.time() - float(entry.get("stored_at", 0))
        if age > self._ttl:
            return None
        return entry, age

    @staticmethod
    def _replayable_headers(response: httpx.Response) -> list[tuple[str, str]]:
        return [(k, v) for k, v in response.headers.items() if k.lower() not in _DROP_HEADERS]

    def _store(self, path: Path, response: httpx.Response, body: bytes) -> None:
        entry = {
            "stored_at": time.time(),
            "status": response.status_code,
            "headers": self._replayable_headers(response),
            "body": base64.b64encode(body).decode("ascii"),
        }
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            # Write-then-rename so a crash mid-write can't leave a torn entry
            # that a later run would read as valid.
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(entry), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass  # An unwritable cache dir degrades to no caching, never a failure.

    def close(self) -> None:
        self._inner.close()
