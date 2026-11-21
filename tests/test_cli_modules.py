from __future__ import annotations

import pathlib
from types import SimpleNamespace

import pytest

from robinshood.core.shell import run_command, safe_target
from robinshood.core.types import RunContext
from robinshood.modules.archive import gau
from robinshood.modules.crawl import photon
from robinshood.modules.infra import httpx_probe
from robinshood.modules.subdomain import amass, subfinder
from robinshood.modules.username import sherlock

SHERLOCK_OUTPUT = """\
[*] Checking username testuser on:

[+] GitHub: https://github.com/testuser
[+] Reddit: https://reddit.com/user/testuser
[-] Facebook: Not Found!
[*] Search completed with 2 results
"""


def test_sherlock_parses_found_profiles(mock_ctx):
    ctx = mock_ctx({}, exec_output=SHERLOCK_OUTPUT)
    findings = sherlock.run("testuser", ctx)
    assert [f.value for f in findings] == [
        "https://github.com/testuser",
        "https://reddit.com/user/testuser",
    ]
    assert {f.type for f in findings} == {"profile"}


def test_sherlock_ignores_not_found_and_status_lines(mock_ctx):
    ctx = mock_ctx({}, exec_output=SHERLOCK_OUTPUT)
    findings = sherlock.run("testuser", ctx)
    assert all("Not Found" not in f.value for f in findings)
    assert len(findings) == 2


def test_sherlock_flags_hits_as_unverified(mock_ctx):
    """sherlock is known for false positives — hits must not claim confidence."""
    ctx = mock_ctx({}, exec_output=SHERLOCK_OUTPUT)
    findings = sherlock.run("testuser", ctx)
    assert all(f.confidence == "Unverified" for f in findings)


def test_sherlock_runs_in_a_temp_dir(mock_ctx):
    calls: list = []
    ctx = mock_ctx({}, exec_output=SHERLOCK_OUTPUT, exec_calls=calls)
    sherlock.run("testuser", ctx)
    assert calls[0][0] == "sherlock"
    assert "testuser" in calls[0]


def test_subfinder_parses_and_dedupes(mock_ctx):
    output = "api.example.com\nwww.example.com\napi.example.com\nexample.com\n"
    ctx = mock_ctx({}, exec_output=output)
    findings = subfinder.run("example.com", ctx)
    assert [f.value for f in findings] == ["api.example.com", "www.example.com"]


def test_subfinder_stays_passive(mock_ctx):
    """No -active flag: subfinder must not resolve against the target's own NS."""
    calls: list = []
    ctx = mock_ctx({}, exec_output="", exec_calls=calls)
    subfinder.run("example.com", ctx)
    assert "-active" not in calls[0]
    assert calls[0] == ["subfinder", "-d", "example.com", "-silent"]


def test_subfinder_empty_output_is_not_an_error(mock_ctx):
    ctx = mock_ctx({}, exec_output="")
    assert subfinder.run("example.com", ctx) == []


@pytest.mark.parametrize("bad", ["-oN", "--output", "  "])
def test_safe_target_rejects_flag_like_and_empty_targets(bad):
    with pytest.raises(ValueError):
        safe_target(bad)


def test_safe_target_allows_normal_values():
    assert safe_target("  example.com ") == "example.com"


def test_missing_binary_raises_actionable_error():
    with pytest.raises(RuntimeError, match="not on PATH"):
        run_command(["robinshood-definitely-not-a-real-binary", "x"])


def test_failed_command_uses_stdout_diagnostic_when_stderr_is_empty(monkeypatch):
    monkeypatch.setattr("robinshood.core.shell.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        "robinshood.core.shell.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=9,
            stdout=";; no servers could be reached\n",
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="no servers could be reached"):
        run_command(["dig", "example.com"])


def test_modules_refuse_flag_like_targets(mock_ctx):
    ctx = mock_ctx({}, exec_output="")
    with pytest.raises(ValueError):
        sherlock.run("-oN", ctx)
    with pytest.raises(ValueError):
        subfinder.run("-d", ctx)
    with pytest.raises(ValueError):
        amass.run("-d", ctx)
    with pytest.raises(ValueError):
        gau.run("--fc", ctx)
    with pytest.raises(ValueError):
        httpx_probe.run("-u", ctx)
    with pytest.raises(ValueError):
        photon.run("--dns", ctx)


# ── amass ────────────────────────────────────────────────────────

def test_amass_parses_and_dedupes(mock_ctx):
    output = "www.obversarystudios.org\nmail.obversarystudios.org\nwww.obversarystudios.org\n"
    ctx = mock_ctx({}, exec_output=output)
    findings = amass.run("obversarystudios.org", ctx)
    assert [f.value for f in findings] == ["www.obversarystudios.org", "mail.obversarystudios.org"]
    assert {f.type for f in findings} == {"domain"}


def test_amass_stays_passive(mock_ctx):
    calls: list = []
    ctx = mock_ctx({}, exec_output="", exec_calls=calls)
    amass.run("obversarystudios.org", ctx)
    assert calls[0] == ["amass", "enum", "-passive", "-d", "obversarystudios.org", "-silent"]
    assert "-active" not in calls[0]


def test_amass_filters_non_hostname_lines(mock_ctx):
    output = "OWASP Amass v4.2.0 [+] 1 name discovered\nwww.obversarystudios.org\n"
    ctx = mock_ctx({}, exec_output=output)
    findings = amass.run("obversarystudios.org", ctx)
    assert [f.value for f in findings] == ["www.obversarystudios.org"]


def test_amass_empty_output_is_not_an_error(mock_ctx):
    ctx = mock_ctx({}, exec_output="")
    assert amass.run("obversarystudios.org", ctx) == []


# ── gau ──────────────────────────────────────────────────────────

def test_gau_parses_and_dedupes(mock_ctx):
    output = (
        "https://obversarystudios.org/a\n"
        "https://obversarystudios.org/b\n"
        "https://obversarystudios.org/a\n"
    )
    ctx = mock_ctx({}, exec_output=output)
    findings = gau.run("obversarystudios.org", ctx)
    assert [f.value for f in findings] == [
        "https://obversarystudios.org/a",
        "https://obversarystudios.org/b",
    ]
    assert {f.type for f in findings} == {"archived_url"}


def test_gau_invocation_has_no_subs_flag(mock_ctx):
    calls: list = []
    ctx = mock_ctx({}, exec_output="", exec_calls=calls)
    gau.run("obversarystudios.org", ctx)
    assert calls[0] == ["gau", "obversarystudios.org"]


def test_gau_empty_output_is_not_an_error(mock_ctx):
    ctx = mock_ctx({}, exec_output="")
    assert gau.run("obversarystudios.org", ctx) == []


# ── httpx_probe ──────────────────────────────────────────────────

def test_httpx_probe_parses_json_lines(mock_ctx):
    output = (
        '{"url":"https://obversarystudios.org","input":"obversarystudios.org",'
        '"status_code":200,"title":"Home"}\n'
    )
    ctx = mock_ctx({}, exec_output=output)
    findings = httpx_probe.run("obversarystudios.org", ctx)
    assert [f.value for f in findings] == ["https://obversarystudios.org"]
    assert findings[0].type == "url"
    assert findings[0].raw["status_code"] == 200


def test_httpx_probe_is_flagged_not_passive():
    assert httpx_probe.MODULE.passive is False


def test_httpx_probe_falls_back_to_input_field(mock_ctx):
    output = '{"input":"obversarystudios.org","status_code":0,"failed":true}\n'
    ctx = mock_ctx({}, exec_output=output)
    findings = httpx_probe.run("obversarystudios.org", ctx)
    assert findings[0].value == "obversarystudios.org"


def test_httpx_probe_empty_output_is_not_an_error(mock_ctx):
    ctx = mock_ctx({}, exec_output="")
    assert httpx_probe.run("obversarystudios.org", ctx) == []


# ── photon ───────────────────────────────────────────────────────

def _photon_ctx(intel: str | None, internal: str | None) -> tuple[RunContext, list]:
    calls: list = []

    def fake_exec(argv, timeout=None, cwd=None):
        calls.append(argv)
        if intel is not None:
            pathlib.Path(cwd, "intel.txt").write_text(intel, encoding="utf-8")
        if internal is not None:
            pathlib.Path(cwd, "internal.txt").write_text(internal, encoding="utf-8")
        return ""

    return RunContext(http=None, env={}, exec=fake_exec), calls


def test_photon_parses_intel_emails_and_internal_urls():
    # Photon's real intel.txt format is "<page-url>:EMAIL:<address>" (verified
    # against a live crawl) — the page URL itself contains "://".
    ctx, calls = _photon_ctx(
        intel=(
            "https://obversarystudios.org/contact:EMAIL:admin@obversarystudios.org\n"
            "https://obversarystudios.org/about:EMAIL:sales@obversarystudios.org\n"
        ),
        internal="https://obversarystudios.org/about\nhttps://obversarystudios.org/about\n",
    )
    findings = photon.run("obversarystudios.org", ctx)
    emails = {f.value for f in findings if f.type == "email"}
    urls = [f.value for f in findings if f.type == "url"]
    assert emails == {"admin@obversarystudios.org", "sales@obversarystudios.org"}
    assert urls == ["https://obversarystudios.org/about"]
    assert all(f.confidence == "Unverified" for f in findings)
    assert calls[0][:3] == ["photon", "-u", "https://obversarystudios.org"]


def test_photon_missing_output_files_is_not_an_error():
    ctx, _ = _photon_ctx(intel=None, internal=None)
    assert photon.run("obversarystudios.org", ctx) == []


def test_photon_ignores_non_email_intel_lines():
    # e.g. an IPV4 intel hit: "<page-url>:IPV4:1.2.3.4"
    ctx, _ = _photon_ctx(intel="https://obversarystudios.org/x:IPV4:1.2.3.4\n", internal=None)
    findings = photon.run("obversarystudios.org", ctx)
    assert findings == []
