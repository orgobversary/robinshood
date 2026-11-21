from __future__ import annotations

import httpx
import pytest

from robinshood import cli
from robinshood.core.case import Case
from robinshood.core.options import ModuleOptionError, parse_module_options
from robinshood.core.registry import RegisteredModule, load_registry
from robinshood.core.runner import run_module
from robinshood.core.types import Finding, ModuleOption, ModuleSpec, RunContext
from robinshood.modules.archive import gau, wayback_cdx
from robinshood.modules.dns import dig_dns, doh_lookup


def _spec(options: tuple[ModuleOption, ...]) -> ModuleSpec:
    return ModuleSpec(
        name="option_test",
        category="test",
        description="test",
        consumes="domain",
        produces=("value",),
        options=options,
    )


def test_option_parser_validates_and_normalizes_types():
    spec = _spec(
        (
            ModuleOption("enabled", "", kind="bool", default=False),
            ModuleOption("workers", "", kind="int", minimum=1, maximum=5),
            ModuleOption("source", "", kind="choice", choices=("One", "Two")),
            ModuleOption("records", "", kind="choice_list", choices=("A", "MX")),
        )
    )

    assert parse_module_options(
        spec,
        ["enabled=yes", "workers=3", "source=two", "records=mx,A,mx"],
    ) == {
        "enabled": True,
        "workers": 3,
        "source": "Two",
        "records": ("MX", "A"),
    }


@pytest.mark.parametrize(
    "raw, message",
    [
        (["missing"], "NAME=VALUE"),
        (["unknown=x"], "has no option"),
        (["workers=0"], "at least 1"),
        (["workers=6"], "at most 5"),
        (["enabled=maybe"], "true/false"),
        (["source=three"], "must be one of"),
        (["workers=2", "workers=3"], "more than once"),
    ],
)
def test_option_parser_rejects_invalid_values(raw, message):
    spec = _spec(
        (
            ModuleOption("enabled", "", kind="bool"),
            ModuleOption("workers", "", kind="int", minimum=1, maximum=5),
            ModuleOption("source", "", kind="choice", choices=("one", "two")),
        )
    )
    with pytest.raises(ModuleOptionError, match=message):
        parse_module_options(spec, raw)


def test_option_definition_rejects_an_invalid_default():
    with pytest.raises(ValueError, match="default"):
        ModuleOption(
            "record_type",
            "",
            kind="choice",
            default="AXFR",
            choices=("A", "MX"),
        )


def test_runner_applies_defaults_and_records_effective_options(tmp_path):
    spec = _spec(
        (
            ModuleOption("enabled", "", kind="bool", default=False),
            ModuleOption("records", "", kind="choice_list", default=("A",), choices=("A", "MX")),
        )
    )

    def run(target, ctx):
        assert ctx.options == {"enabled": True, "records": ("A",)}
        return [Finding(type="value", value="ok", module=spec.name, target=target)]

    entry = RegisteredModule(spec=spec, run=run)
    result = run_module(
        entry,
        "example.com",
        RunContext(http=httpx.Client(), env={}, options={"enabled": True}),
    )

    assert result.ok
    assert result.options == {"enabled": True, "records": ["A"]}
    case = Case.open(tmp_path, "example.com")
    case.record_result(result)
    assert case.load_evidence()[0]["options"] == {
        "enabled": True,
        "records": ["A"],
    }


def test_dns_doh_can_select_record_types(mock_ctx):
    ctx = mock_ctx(
        {"type=CAA": {"Answer": [{"data": '0 issue "letsencrypt.org"'}]}},
    )
    ctx.options = {"record_types": ("CAA",)}

    findings = doh_lookup.run("example.com", ctx)

    assert [(finding.type, finding.value) for finding in findings] == [
        ("caa", '0 issue "letsencrypt.org"')
    ]


def test_gau_builds_only_validated_option_flags():
    calls = []
    ctx = RunContext(
        http=httpx.Client(),
        env={},
        options={
            "include_subdomains": True,
            "providers": ("wayback", "otx"),
            "threads": 4,
        },
        exec=lambda argv, timeout=None, cwd=None: calls.append(argv) or "",
    )

    gau.run("example.com", ctx)

    assert calls == [[
        "gau",
        "--subs",
        "--providers",
        "wayback,otx",
        "--threads",
        "4",
        "example.com",
    ]]


def test_wayback_cdx_options_become_query_parameters():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[])

    ctx = RunContext(
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        env={},
        options={"limit": 200, "collapse": "none"},
    )

    assert wayback_cdx.run("example.com", ctx) == []
    assert requests[0].url.params["limit"] == "200"
    assert "collapse" not in requests[0].url.params


def test_dig_axfr_uses_explicit_server_and_parses_zone_records():
    calls = []
    stdout = """\
example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
example.com. 3600 IN NS ns1.example.com.
www.example.com. 300 IN A 192.0.2.10
example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
"""
    ctx = RunContext(
        http=httpx.Client(),
        env={},
        options={
            "record_type": "AXFR",
            "server": "ns1.example.com",
            "transport": "auto",
            "dnssec": True,
            "timeout": 10,
            "tries": 2,
        },
        exec=lambda argv, timeout=None, cwd=None: calls.append((argv, timeout)) or stdout,
    )

    findings = dig_dns.run("example.com", ctx)

    argv, command_timeout = calls[0]
    assert argv == [
        "dig",
        "-r",
        "+noall",
        "+answer",
        "+comments",
        "+timeout=10",
        "+tries=2",
        "@ns1.example.com",
        "example.com",
        "AXFR",
        "+dnssec",
    ]
    assert command_timeout == 30.0
    assert [(finding.type, finding.value) for finding in findings] == [
        ("soa", "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"),
        ("ns", "ns1.example.com"),
        ("ip", "192.0.2.10"),
    ]
    assert dig_dns.MODULE.passive is False


def test_dig_can_force_dns_over_https_transport():
    calls = []
    ctx = RunContext(
        http=httpx.Client(),
        env={},
        options={
            "record_type": "A",
            "server": "1.1.1.1",
            "transport": "https",
        },
        exec=lambda argv, timeout=None, cwd=None: calls.append(argv) or "",
    )
    findings = dig_dns.run("example.com", ctx)
    assert "+https" in calls[0]
    assert findings == []


def test_dig_rejects_axfr_over_non_tcp_transport():
    with pytest.raises(ModuleOptionError, match="transport"):
        dig_dns.validate_options(
            {
                "record_type": "AXFR",
                "server": "ns1.example.com",
                "transport": "https",
            }
        )


def test_dig_axfr_requires_an_explicit_authoritative_server():
    ctx = RunContext(
        http=httpx.Client(),
        env={},
        options={"record_type": "AXFR"},
        exec=lambda argv, timeout=None, cwd=None: pytest.fail("dig should not run"),
    )
    with pytest.raises(RuntimeError, match="AXFR requires"):
        dig_dns.run("example.com", ctx)


def test_dig_axfr_treats_dns_error_status_as_failure():
    stdout = """\
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 1
; Transfer failed.
"""
    ctx = RunContext(
        http=httpx.Client(),
        env={},
        options={
            "record_type": "AXFR",
            "server": "ns1.example.com",
        },
        exec=lambda argv, timeout=None, cwd=None: stdout,
    )
    with pytest.raises(RuntimeError, match="DNS status FORMERR"):
        dig_dns.run("example.com", ctx)


def test_dig_axfr_rejects_silent_empty_transfer():
    ctx = RunContext(
        http=httpx.Client(),
        env={},
        options={
            "record_type": "AXFR",
            "server": "ns1.example.com",
        },
        exec=lambda argv, timeout=None, cwd=None: "",
    )
    with pytest.raises(RuntimeError, match="no zone records"):
        dig_dns.run("example.com", ctx)


def test_options_command_describes_dig(capsys):
    assert cli.main(["options", "dig_dns"]) == 0
    output = capsys.readouterr().out
    assert "record_type" in output
    assert "AXFR" in output
    assert "server" in output


def test_options_command_summarizes_every_module(capsys):
    assert cli.main(["options"]) == 0
    output = capsys.readouterr().out
    assert "dig_dns" in output
    assert "record_type" in output
    assert "rdap_ip" in output
    assert "(none)" in output


def test_single_active_run_requires_confirmation_before_creating_case(tmp_path, capsys):
    assert cli.main([
        "--cases-dir",
        str(tmp_path),
        "run",
        "dig_dns",
        "example.com",
    ]) == 2
    output = capsys.readouterr()
    assert "refusing to run active modules" in output.err
    assert list(tmp_path.iterdir()) == []


def test_axfr_cross_option_validation_happens_before_case_creation(tmp_path, capsys):
    assert cli.main([
        "--cases-dir",
        str(tmp_path),
        "run",
        "dig_dns",
        "example.com",
        "--option",
        "record_type=AXFR",
        "--yes",
    ]) == 2
    output = capsys.readouterr()
    assert "AXFR requires server" in output.err
    assert list(tmp_path.iterdir()) == []


def test_dig_server_cannot_be_a_flag(tmp_path, capsys):
    assert cli.main([
        "--cases-dir",
        str(tmp_path),
        "run",
        "dig_dns",
        "example.com",
        "--option",
        "server=-f",
        "--yes",
    ]) == 2
    output = capsys.readouterr()
    assert "invalid dig_dns server" in output.err
    assert list(tmp_path.iterdir()) == []


def test_sweep_options_are_scoped_by_module():
    entries = list(load_registry())
    parsed = cli._parse_sweep_options(
        entries,
        ["dns_doh.record_types=A,MX", "gau.include_subdomains=true"],
    )
    assert parsed == {
        "dns_doh": {"record_types": ("A", "MX")},
        "gau": {"include_subdomains": True},
    }
