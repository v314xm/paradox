"""Тесты реестра провайдеров."""
from paradox.integrations.registry import (
    REGISTRY,
    get_provider,
    list_providers,
)


def test_known_providers_registered():
    assert "shodan_internetdb" in REGISTRY
    assert "abuseipdb" in REGISTRY
    assert "virustotal" in REGISTRY


def test_get_provider_returns_class():
    cls = get_provider("shodan_internetdb")
    assert cls is not None
    inst = cls()
    assert inst.name == "shodan_internetdb"


def test_get_provider_unknown_is_none():
    assert get_provider("nope") is None


def test_list_providers_sorted():
    names = list_providers()
    assert names == sorted(names)
    assert "virustotal" in names


def test_registry_names_match_instances():
    for name, cls in REGISTRY.items():
        assert cls().name == name, f"{cls.__name__}.name != {name}"
