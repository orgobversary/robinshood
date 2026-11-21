from __future__ import annotations

import argparse
import sys

import httpx

from robinshood import cli as cli_module
from robinshood.cli import _proxy, _user_agent, cmd_whoami
from robinshood.core.http import USER_AGENT, build_client
from robinshood.core.shell import proxy_env, run_command


def _whoami_args(**overrides):
    defaults = dict(
        proxy=None, user_agent=None, json=False, timeout=5.0,
        tor_rotate=False, tor_control=None, tor_control_password=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_build_client_accepts_http_proxy():
    with build_client(proxy="http://127.0.0.1:8080") as client:
        assert client is not None


def test_build_client_accepts_socks5_proxy():
    # socksio (via the httpx[socks] dependency) makes this construct without
    # raising — no request is made, so no network is touched.
    with build_client(proxy="socks5h://127.0.0.1:9050") as client:
        assert client is not None


def test_build_client_default_has_no_proxy():
    with build_client() as client:
        assert client is not None


def test_build_client_default_user_agent():
    with build_client() as client:
        assert client.headers["User-Agent"] == USER_AGENT


def test_build_client_custom_user_agent():
    with build_client(user_agent="Mozilla/5.0 (generic)") as client:
        assert client.headers["User-Agent"] == "Mozilla/5.0 (generic)"


def test_proxy_env_covers_both_cases():
    env = proxy_env("socks5h://127.0.0.1:9050")
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        assert env[var] == "socks5h://127.0.0.1:9050"


def test_run_command_without_env_behaves_as_before():
    out = run_command([sys.executable, "-c", "print('hello')"])
    assert out.strip() == "hello"


def test_run_command_env_is_merged_into_subprocess():
    out = run_command(
        [sys.executable, "-c", "import os; print(os.environ.get('HTTP_PROXY', ''))"],
        env={"HTTP_PROXY": "socks5h://127.0.0.1:9050"},
    )
    assert out.strip() == "socks5h://127.0.0.1:9050"


def test_run_command_env_does_not_wipe_inherited_environment():
    # Merged, not replaced — PATH (or some other pre-existing var) survives.
    out = run_command(
        [sys.executable, "-c", "import os; print('PATH' in os.environ)"],
        env={"HTTP_PROXY": "http://127.0.0.1:1"},
    )
    assert out.strip() == "True"


def test_cli_proxy_flag_beats_env_var(monkeypatch):
    monkeypatch.setenv("ROBINSHOOD_PROXY", "socks5h://from-env:9050")
    args = argparse.Namespace(proxy="socks5h://from-flag:9050", user_agent=None)
    assert _proxy(args) == "socks5h://from-flag:9050"


def test_cli_proxy_falls_back_to_env_var(monkeypatch):
    monkeypatch.setenv("ROBINSHOOD_PROXY", "socks5h://from-env:9050")
    args = argparse.Namespace(proxy=None, user_agent=None)
    assert _proxy(args) == "socks5h://from-env:9050"


def test_cli_proxy_none_when_neither_set(monkeypatch):
    monkeypatch.delenv("ROBINSHOOD_PROXY", raising=False)
    args = argparse.Namespace(proxy=None, user_agent=None)
    assert _proxy(args) is None


def test_cli_user_agent_flag_beats_env_var(monkeypatch):
    monkeypatch.setenv("ROBINSHOOD_USER_AGENT", "from-env")
    args = argparse.Namespace(proxy=None, user_agent="from-flag")
    assert _user_agent(args) == "from-flag"


# ── cmd_whoami ──────────────────────────────────────────────────
# ipinfo.io actively blocks known Tor exit nodes with a bare 403 (confirmed
# live) — cmd_whoami must surface that as an error, never silently show
# blank fields as if nothing were wrong.

def _mock_build_client(status: int, body: bytes, urls: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return httpx.Response(status, content=body)

    def _build(timeout=None, proxy=None, user_agent=None):
        return httpx.Client(transport=httpx.MockTransport(handler))

    return _build


def test_cmd_whoami_reports_non_200_instead_of_blank_fields(monkeypatch, capsys):
    urls: list[str] = []
    monkeypatch.setattr(cli_module, "build_client", _mock_build_client(403, b"Forbidden", urls))
    rc = cmd_whoami(_whoami_args(proxy="socks5h://127.0.0.1:9050"))
    captured = capsys.readouterr()
    assert rc == 1
    assert "403" in captured.err
    assert captured.out == ""  # nothing printed as if it had succeeded


def test_cmd_whoami_queries_check_torproject_when_proxied(monkeypatch):
    urls: list[str] = []
    monkeypatch.setattr(
        cli_module, "build_client", _mock_build_client(200, b'{"IsTor": true, "IP": "1.2.3.4"}', urls)
    )
    rc = cmd_whoami(_whoami_args(proxy="socks5h://127.0.0.1:9050"))
    assert rc == 0
    assert urls == ["https://check.torproject.org/api/ip"]


def test_cmd_whoami_queries_ipinfo_when_unproxied(monkeypatch):
    urls: list[str] = []
    monkeypatch.setattr(
        cli_module, "build_client", _mock_build_client(200, b'{"ip": "1.2.3.4", "org": "Example Org"}', urls)
    )
    rc = cmd_whoami(_whoami_args(proxy=None))
    assert rc == 0
    assert urls == ["https://ipinfo.io/json"]


def test_cmd_whoami_json_output_includes_source(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_module, "build_client",
        _mock_build_client(200, b'{"IsTor": true, "IP": "1.2.3.4"}', []),
    )
    rc = cmd_whoami(_whoami_args(proxy="socks5h://127.0.0.1:9050", json=True))
    captured = capsys.readouterr()
    assert rc == 0
    assert '"source": "check.torproject.org"' in captured.out
    assert '"IsTor": true' in captured.out
