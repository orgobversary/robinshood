from __future__ import annotations

import argparse
import socket
import threading

import pytest

from robinshood.cli import _tor_control_addr, _tor_control_password, _tor_rotate
from robinshood.core.tor import TorControlError, new_identity


def _fake_control_server(port: int, *, reject_auth: bool = False, reject_signal: bool = False):
    """A minimal stand-in for Tor's control port — enough to exercise
    new_identity()'s wire protocol without a real Tor daemon."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready = threading.Event()

    def _serve():
        ready.set()
        conn, _ = srv.accept()
        try:
            fh = conn.makefile("rw", encoding="ascii", newline="\r\n")
            fh.readline()  # AUTHENTICATE "..."
            fh.write("515 Authentication failed\r\n" if reject_auth else "250 OK\r\n")
            fh.flush()
            if reject_auth:
                return
            fh.readline()  # SIGNAL NEWNYM
            fh.write("552 Unrecognized signal\r\n" if reject_signal else "250 OK\r\n")
            fh.flush()
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    ready.wait()
    return thread


def test_new_identity_succeeds_against_a_well_behaved_control_port():
    port = 19151
    thread = _fake_control_server(port)
    new_identity(("127.0.0.1", port), password=None)
    thread.join(timeout=2)


def test_new_identity_raises_on_auth_failure():
    port = 19152
    _fake_control_server(port, reject_auth=True)
    with pytest.raises(TorControlError, match="authentication failed"):
        new_identity(("127.0.0.1", port), password="wrong")


def test_new_identity_raises_on_signal_rejection():
    port = 19153
    _fake_control_server(port, reject_signal=True)
    with pytest.raises(TorControlError, match="NEWNYM signal failed"):
        new_identity(("127.0.0.1", port))


def test_new_identity_raises_a_clear_error_when_unreachable():
    with pytest.raises(TorControlError, match="could not reach Tor"):
        new_identity(("127.0.0.1", 19199))  # nothing listening


def test_cli_tor_rotate_flag(monkeypatch):
    monkeypatch.delenv("ROBINSHOOD_TOR_ROTATE", raising=False)
    assert _tor_rotate(argparse.Namespace(tor_rotate=True)) is True
    assert _tor_rotate(argparse.Namespace(tor_rotate=False)) is False


def test_cli_tor_rotate_env_fallback(monkeypatch):
    monkeypatch.setenv("ROBINSHOOD_TOR_ROTATE", "1")
    assert _tor_rotate(argparse.Namespace(tor_rotate=False)) is True


def test_cli_tor_control_addr_parses_host_port():
    args = argparse.Namespace(tor_control="10.0.0.5:9999")
    assert _tor_control_addr(args) == ("10.0.0.5", 9999)


def test_cli_tor_control_addr_default(monkeypatch):
    monkeypatch.delenv("ROBINSHOOD_TOR_CONTROL", raising=False)
    assert _tor_control_addr(argparse.Namespace(tor_control=None)) == ("127.0.0.1", 9051)


def test_cli_tor_control_password_precedence(monkeypatch):
    monkeypatch.setenv("ROBINSHOOD_TOR_CONTROL_PASSWORD", "from-env")
    args = argparse.Namespace(tor_control_password="from-flag")
    assert _tor_control_password(args) == "from-flag"
