from __future__ import annotations

import pytest

from robinshood.core.registry import load_registry
from robinshood.core.types import INPUT_TYPES, ModuleSpec


def test_registry_loads_all_modules():
    registry = load_registry()
    assert len(registry) >= 9
    assert "dns_doh" in registry
    assert "rdap_ip" in registry


def test_every_module_spec_is_valid():
    for entry in load_registry():
        spec = entry.spec
        assert spec.consumes in INPUT_TYPES
        assert spec.produces
        assert spec.description
        assert callable(entry.run)


def test_consuming_and_producing_lookup():
    registry = load_registry()
    domain_modules = {e.spec.name for e in registry.consuming("domain")}
    assert {"dns_doh", "rdap_domain", "crtsh_subdomains"} <= domain_modules

    ip_producers = {e.spec.name for e in registry.producing("ip")}
    assert "dns_doh" in ip_producers


def test_spec_rejects_unknown_consumes_type():
    with pytest.raises(ValueError, match="consumes"):
        ModuleSpec(
            name="bad",
            category="x",
            description="d",
            consumes="not-a-type",
            produces=("ip",),
        )


def test_spec_rejects_empty_produces():
    with pytest.raises(ValueError, match="produces"):
        ModuleSpec(name="bad", category="x", description="d", consumes="ip", produces=())
