"""Реестр содержит все 9 провайдеров."""
from paradox.integrations.registry import REGISTRY, list_providers


def test_all_nine_present():
    expected = {
        "shodan_internetdb", "abuseipdb", "virustotal",
        "greynoise", "alienvault_otx", "urlscan",
        "urlhaus", "malwarebazaar", "threatfox",
    }
    assert set(REGISTRY) == expected


def test_registry_names_match_instances():
    for name, cls in REGISTRY.items():
        try:
            inst = cls()
        except TypeError:
            inst = cls(auth_key="")
        assert inst.name == name


def test_list_providers_sorted():
    assert list_providers() == sorted(list_providers())
