from __future__ import annotations

from robinshood.core.pivot import suggest_next
from robinshood.core.registry import load_registry
from robinshood.core.types import Finding


def _names(suggestions):
    return {s.module.spec.name for s in suggestions}


def test_ip_finding_suggests_ip_consuming_modules():
    registry = load_registry()
    findings = [Finding(type="ip", value="8.8.8.8", module="dns_doh", target="example.com")]
    assert {"rdap_ip", "shodan_internetdb", "ipinfo_geo"} <= _names(suggest_next(registry, findings))


def test_subdomain_finding_suggests_domain_modules():
    registry = load_registry()
    findings = [
        Finding(type="domain", value="api.example.com", module="crtsh_subdomains", target="example.com")
    ]
    assert "dns_doh" in _names(suggest_next(registry, findings))


def test_module_is_never_suggested_against_its_own_findings():
    """subfinder finding 25k subdomains must not propose re-running subfinder."""
    registry = load_registry()
    findings = [
        Finding(type="domain", value=f"h{i}.example.com", module="subfinder", target="example.com")
        for i in range(3)
    ]
    suggested = _names(suggest_next(registry, findings))
    assert "subfinder" not in suggested
    assert "dns_doh" in suggested


def test_suggestion_reports_count_and_sample():
    registry = load_registry()
    findings = [
        Finding(type="ip", value="1.1.1.1", module="dns_doh", target="t"),
        Finding(type="ip", value="2.2.2.2", module="dns_doh", target="t"),
    ]
    suggestion = next(s for s in suggest_next(registry, findings) if s.module.spec.name == "rdap_ip")
    assert suggestion.count == 2
    assert suggestion.sample_value == "1.1.1.1"
    assert "2 ips" in suggestion.describe()


def test_single_value_suggestion_describes_plainly():
    registry = load_registry()
    findings = [Finding(type="ip", value="1.1.1.1", module="dns_doh", target="t")]
    suggestion = next(s for s in suggest_next(registry, findings) if s.module.spec.name == "rdap_ip")
    assert suggestion.describe() == "rdap_ip(1.1.1.1)"


def test_duplicate_values_are_counted_once():
    registry = load_registry()
    findings = [
        Finding(type="ip", value="1.1.1.1", module="dns_doh", target="t"),
        Finding(type="ip", value="1.1.1.1", module="dns_doh", target="t"),
    ]
    suggestion = next(s for s in suggest_next(registry, findings) if s.module.spec.name == "rdap_ip")
    assert suggestion.count == 1


def test_suggestions_are_deduplicated_by_module():
    registry = load_registry()
    findings = [
        Finding(type="ip", value="1.1.1.1", module="dns_doh", target="t"),
        Finding(type="ip", value="2.2.2.2", module="dns_doh", target="t"),
    ]
    names = [s.module.spec.name for s in suggest_next(registry, findings)]
    assert len(names) == len(set(names))


def test_unpivotable_finding_type_yields_nothing():
    registry = load_registry()
    findings = [Finding(type="txt", value="v=spf1 -all", module="dns_doh", target="t")]
    assert suggest_next(registry, findings) == []
