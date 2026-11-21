from __future__ import annotations

import json
import re

import httpx
import pytest

from robinshood.core.types import RunContext


@pytest.fixture
def mock_ctx():
    """Builds a RunContext whose httpx.Client is backed by a canned-response
    transport. Tests must never touch the live network."""

    def _build(
        routes: dict[str, object],
        env: dict | None = None,
        exec_output: str | None = None,
        exec_calls: list | None = None,
    ) -> RunContext:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            for path_fragment, payload in routes.items():
                # Boundary-aware so a route of "type=A" does not also match "type=AAAA".
                if re.search(re.escape(path_fragment) + r"(?![A-Za-z0-9])", url):
                    if isinstance(payload, int):
                        return httpx.Response(payload)
                    return httpx.Response(200, content=json.dumps(payload))
            # Unrouted URLs answer "valid response, no data" so a module that
            # queries several endpoints only needs the ones under test routed.
            return httpx.Response(200, content=json.dumps({}))

        def fake_exec(argv, timeout=None, cwd=None):
            if exec_calls is not None:
                exec_calls.append(argv)
            if exec_output is None:
                raise AssertionError(f"unexpected subprocess call: {argv}")
            return exec_output

        client = httpx.Client(transport=httpx.MockTransport(handler))
        return RunContext(http=client, env=env or {}, exec=fake_exec)

    return _build
