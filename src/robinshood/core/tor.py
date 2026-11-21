from __future__ import annotations

import socket

DEFAULT_CONTROL_ADDR = ("127.0.0.1", 9051)


class TorControlError(RuntimeError):
    pass


def new_identity(
    addr: tuple[str, int] = DEFAULT_CONTROL_ADDR,
    password: str | None = None,
    timeout: float = 5.0,
) -> None:
    """Requests a fresh Tor circuit (SIGNAL NEWNYM) over the control port, so
    the next connection made through Tor's SOCKS proxy exits from a different
    relay. Tor rate-limits NEWNYM to roughly once per 10s — calling this more
    often than that is a silent no-op on Tor's side, not an error here.

    Hand-rolled rather than depending on `stem`: this is the entire protocol
    robinshood needs — connect, AUTHENTICATE, SIGNAL NEWNYM, read two "250"
    lines — not worth a dependency for.
    """
    try:
        with socket.create_connection(addr, timeout=timeout) as sock:
            fh = sock.makefile("rw", encoding="ascii", newline="\r\n")
            fh.write(f'AUTHENTICATE "{password or ""}"\r\n')
            fh.flush()
            resp = fh.readline()
            if not resp.startswith("250"):
                raise TorControlError(
                    f"Tor control authentication failed at {addr[0]}:{addr[1]}: {resp.strip()!r} "
                    f"— check $ROBINSHOOD_TOR_CONTROL_PASSWORD against torrc's HashedControlPassword."
                )

            fh.write("SIGNAL NEWNYM\r\n")
            fh.flush()
            resp = fh.readline()
            if not resp.startswith("250"):
                raise TorControlError(f"Tor NEWNYM signal failed: {resp.strip()!r}")
    except OSError as exc:
        raise TorControlError(
            f"could not reach Tor's control port at {addr[0]}:{addr[1]} — is Tor running "
            f"with `ControlPort 9051` enabled in torrc? ({exc})"
        ) from None
