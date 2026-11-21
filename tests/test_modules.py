from __future__ import annotations

import pytest

from robinshood.modules.breach import hibp_breach_check
from robinshood.modules.certs import crtsh_subdomains
from robinshood.modules.dns import doh_lookup
from robinshood.modules.infra import shodan_internetdb
from robinshood.modules.whois import rdap_domain, rdap_ip


def test_dns_doh_parses_answers(mock_ctx):
    ctx = mock_ctx({"type=A": {"Answer": [{"data": "93.184.216.34", "type": 1}]}})
    findings = doh_lookup.run("example.com", ctx)
    ips = [f.value for f in findings if f.type == "ip"]
    assert ips == ["93.184.216.34"]


def test_dns_doh_strips_txt_quotes(mock_ctx):
    ctx = mock_ctx({"type=TXT": {"Answer": [{"data": '"v=spf1 -all"'}]}})
    findings = doh_lookup.run("example.com", ctx)
    txt = [f.value for f in findings if f.type == "txt"]
    assert txt == ["v=spf1 -all"]


def test_rdap_domain_extracts_registrar_and_nameservers(mock_ctx):
    ctx = mock_ctx(
        {
            "rdap.org/domain": {
                "entities": [{"roles": ["registrar"], "handle": "376"}],
                "nameservers": [{"ldhName": "a.iana-servers.net"}],
            }
        }
    )
    findings = rdap_domain.run("example.com", ctx)
    assert {f.type for f in findings} == {"registrar", "nameserver"}
    assert any(f.value == "a.iana-servers.net" for f in findings)


def test_rdap_ip_extracts_netname(mock_ctx):
    ctx = mock_ctx({"rdap.org/ip": {"name": "GOGL", "handle": "NET-8-8-8-0-1"}})
    findings = rdap_ip.run("8.8.8.8", ctx)
    assert findings[0].type == "netname"
    assert findings[0].value == "GOGL"


def test_crtsh_dedupes_and_strips_wildcards(mock_ctx):
    ctx = mock_ctx(
        {
            "crt.sh": [
                {"name_value": "*.example.com\napi.example.com", "id": 1},
                {"name_value": "api.example.com", "id": 2},
                {"name_value": "example.com", "id": 3},
            ]
        }
    )
    findings = crtsh_subdomains.run("example.com", ctx)
    values = [f.value for f in findings]
    assert values == ["api.example.com"]


def test_shodan_internetdb_returns_empty_on_404(mock_ctx):
    ctx = mock_ctx({"internetdb.shodan.io": 404})
    assert shodan_internetdb.run("192.0.2.1", ctx) == []


def test_shodan_internetdb_parses_ports_and_vulns(mock_ctx):
    ctx = mock_ctx(
        {"internetdb.shodan.io": {"ports": [22, 443], "cpes": ["cpe:/a:nginx"], "vulns": ["CVE-2021-1"]}}
    )
    findings = shodan_internetdb.run("8.8.8.8", ctx)
    assert {f.type for f in findings} == {"port", "cpe", "vuln"}


def test_hibp_requires_key(mock_ctx):
    ctx = mock_ctx({}, env={})
    with pytest.raises(RuntimeError, match="HIBP_API_KEY"):
        hibp_breach_check.run("user@example.com", ctx)


def test_hibp_reports_clean_email_on_404(mock_ctx):
    ctx = mock_ctx({"breachedaccount": 404}, env={"HIBP_API_KEY": "x"})
    findings = hibp_breach_check.run("user@example.com", ctx)
    assert "not found" in findings[0].value
