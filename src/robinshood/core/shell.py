from __future__ import annotations

import os
import shutil
import subprocess

_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


def proxy_env(url: str) -> dict[str, str]:
    """Both cased variants, covering Go's net/http-based CLI tools (amass,
    subfinder, gau, httpx) and Python requests-based ones (sherlock, photon)
    without special-casing any individual tool. Merged into a subprocess's
    environment via run_command's env= — never applied globally to this
    process's own os.environ."""
    return {var: url for var in _PROXY_VARS}


def safe_target(value: str) -> str:
    """Guards against argument injection. Targets are passed as argv elements
    (never through a shell), so quoting is not the risk — a target that looks
    like a flag is: `-oN` as a "username" would be read as an option by the
    wrapped tool."""
    value = value.strip()
    if not value:
        raise ValueError("empty target")
    if value.startswith("-"):
        raise ValueError(f"refusing target that looks like a command-line flag: {value!r}")
    return value


def run_command(
    argv: list[str],
    timeout: float = 300.0,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Runs a local CLI tool and returns its stdout. Never uses shell=True.

    `env`, when given, is merged on top of this process's own environment for
    this one subprocess call only — used to inject proxy_env() without ever
    mutating os.environ itself. `env=None` (the default) passes os.environ
    explicitly, which is behaviorally identical to omitting env= entirely."""
    exe = shutil.which(argv[0])
    if exe is None:
        raise RuntimeError(
            f"{argv[0]!r} is not on PATH — this module wraps a local CLI tool that "
            f"must be installed separately (see README)."
        )
    try:
        proc = subprocess.run(
            [exe, *argv[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=os.environ if env is None else {**os.environ, **env},
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{argv[0]} timed out after {timeout:.0f}s") from None

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().splitlines()
        detail = stderr[-1] if stderr else f"exit code {proc.returncode}"
        raise RuntimeError(f"{argv[0]} failed: {detail}")

    return proc.stdout
