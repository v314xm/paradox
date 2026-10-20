"""Config.enrichment_enabled_providers содержит 9 провайдеров.

6 безключевых + 3 abuse.ch (требуют ABUSECH_AUTH_KEY, но видны
в списке «Настройки → Threat Intel»).
"""
from paradox.config import Config


def test_default_providers_count():
    cfg = Config()
    assert len(cfg.enrichment_enabled_providers) == 9


def test_keyless_providers_enabled_by_default():
    cfg = Config()
    for p in ("shodan_internetdb", "greynoise", "alienvault_otx", "urlscan"):
        assert p in cfg.enrichment_enabled_providers


def test_keyed_providers_in_default():
    """abuseipdb/virustotal требуют ключ, но в списке."""
    cfg = Config()
    for p in ("abuseipdb", "virustotal"):
        assert p in cfg.enrichment_enabled_providers


def test_abusеch_providers_in_default():
    """abuse.ch-провайдеры в списке — но без ключа BaseEnricher.enabled
    возвращает False, поэтому запросы не идут."""
    cfg = Config()
    for p in ("urlhaus", "malwarebazaar", "threatfox"):
        assert p in cfg.enrichment_enabled_providers


def test_all_registry_names_present_in_default():
    """В Config должны быть все имена из REGISTRY — иначе провайдер
    никогда не вызовется."""
    from paradox.integrations.registry import REGISTRY
    cfg = Config()
    missing = set(REGISTRY) - set(cfg.enrichment_enabled_providers)
    assert not missing, f"нет в Config: {sorted(missing)}"
