"""
Тесты Shodan InternetDB и базового оркестратора.

HTTP замокан — никакой сети в тестах.
"""
import time

import pytest

from paradox.config import Config
from paradox.integrations.base import EnrichmentResult
from paradox.integrations.cache import EnrichmentCache
from paradox.integrations.enricher import (
    EnricherOrchestrator,
    collect_iocs_from_findings,
)
from paradox.integrations.shodan_internetdb import (
    ShodanInternetDBEnricher,
)


# ---------- Shodan провайдер ----------

def test_shodan_lookup_success(monkeypatch):
    """Успешный ответ — data заполнена."""
    e = ShodanInternetDBEnricher()
    monkeypatch.setattr(e, "_fetch", lambda ip: (
        {"ports": [53, 443], "hostnames": ["dns.google"]}, None
    ))

    result = e.lookup("8.8.8.8", "ip")
    assert result.ok
    assert result.source == "shodan_internetdb"
    assert result.ioc == "8.8.8.8"
    assert result.data["ports"] == [53, 443]
    assert result.ttl_days == 7


def test_shodan_lookup_404(monkeypatch):
    """404 — не ошибка, просто нет данных."""
    e = ShodanInternetDBEnricher()
    monkeypatch.setattr(e, "_fetch", lambda ip: (None, None))

    result = e.lookup("192.0.2.1", "ip")
    assert result.ok
    assert result.data == {}
    assert result.ttl_days == 1  # negative TTL


def test_shodan_lookup_timeout(monkeypatch):
    """Таймаут — error заполнен."""
    e = ShodanInternetDBEnricher()
    monkeypatch.setattr(e, "_fetch", lambda ip: (None, "timeout"))

    result = e.lookup("8.8.8.8", "ip")
    assert not result.ok
    assert result.error == "timeout"


def test_shodan_lookup_unsupported_type():
    """Domain не поддержан."""
    e = ShodanInternetDBEnricher()
    result = e.lookup("example.com", "domain")
    assert not result.ok
    assert "unsupported" in result.error


# ---------- Оркестратор ----------

class _MockProvider:
    """Mock-провайдер для тестов оркестратора."""
    name = "mock"
    supports = ("ip",)
    ttl_days = 7

    def __init__(self, response_data=None, error=None):
        self.calls = []
        self.response_data = response_data or {"result": "ok"}
        self.error = error

    def lookup(self, ioc, ioc_type):
        self.calls.append((ioc, ioc_type))
        return EnrichmentResult(
            source=self.name, ioc=ioc, ioc_type=ioc_type,
            data=self.response_data,
            fetched_at=time.time(),
            ttl_days=self.ttl_days,
            error=self.error,
        )


def test_orchestrator_basic(tmp_path):
    """Обогащаем IP через mock-провайдер."""
    db = tmp_path / "c.db"
    with EnrichmentCache(db) as cache:
        provider = _MockProvider()
        config = Config()
        # Заменяем набор enabled на "mock"
        from dataclasses import replace
        config = replace(config, enrichment_enabled_providers=frozenset({"mock"}))

        orch = EnricherOrchestrator([provider], cache, config)
        result = orch.enrich([("ip", "8.8.8.8")])

        assert ("ip", "8.8.8.8") in result
        assert len(result[("ip", "8.8.8.8")]) == 1
        assert result[("ip", "8.8.8.8")][0].ok
        assert provider.calls == [("8.8.8.8", "ip")]


def test_orchestrator_cache_hit(tmp_path):
    """Второй запрос того же IOC — из кэша."""
    db = tmp_path / "c.db"
    with EnrichmentCache(db) as cache:
        provider = _MockProvider()
        config = Config()
        from dataclasses import replace
        config = replace(config, enrichment_enabled_providers=frozenset({"mock"}))

        orch = EnricherOrchestrator([provider], cache, config)
        orch.enrich([("ip", "8.8.8.8")])
        orch.enrich([("ip", "8.8.8.8")])

        # Провайдер вызван 1 раз, второй — из кэша
        assert len(provider.calls) == 1
        assert orch.stats["cache_hits"] == 1


def test_orchestrator_dedup_iocs(tmp_path):
    """Дубликаты в списке IOC — дедуплицируются."""
    db = tmp_path / "c.db"
    with EnrichmentCache(db) as cache:
        provider = _MockProvider()
        config = Config()
        from dataclasses import replace
        config = replace(config, enrichment_enabled_providers=frozenset({"mock"}))

        orch = EnricherOrchestrator([provider], cache, config)
        orch.enrich([("ip", "8.8.8.8"), ("ip", "8.8.8.8"), ("ip", "8.8.8.8")])

        assert len(provider.calls) == 1


def test_orchestrator_error_result_not_cached(tmp_path):
    """Ошибочный результат не кладётся в кэш."""
    db = tmp_path / "c.db"
    with EnrichmentCache(db) as cache:
        provider = _MockProvider(error="network down")
        config = Config()
        from dataclasses import replace
        config = replace(config, enrichment_enabled_providers=frozenset({"mock"}))

        orch = EnricherOrchestrator([provider], cache, config)
        orch.enrich([("ip", "8.8.8.8")])

        # Пустой кэш — ошибки не сохраняем
        assert cache.stats()["total"] == 0
        assert orch.stats["errors"] == 1


def test_orchestrator_max_iocs(tmp_path):
    """Не больше enrichment_max_iocs обрабатывается за раз."""
    db = tmp_path / "c.db"
    with EnrichmentCache(db) as cache:
        provider = _MockProvider()
        config = Config()
        from dataclasses import replace
        config = replace(
            config,
            enrichment_enabled_providers=frozenset({"mock"}),
            enrichment_max_iocs=2,
        )

        orch = EnricherOrchestrator([provider], cache, config)
        orch.enrich([
            ("ip", "1.1.1.1"), ("ip", "2.2.2.2"),
            ("ip", "3.3.3.3"), ("ip", "4.4.4.4"),
        ])

        assert len(provider.calls) <= 2


# ---------- collect_iocs_from_findings ----------

def test_collect_iocs_from_findings_basic():
    """Из findings достаём IP и домены."""
    from paradox.models import Finding

    findings = [
        Finding(
            type="suspicious_port", value="1.2.3.4:4444",
            confidence=0.5, evidence={
                "dst_ip": "1.2.3.4", "dst_port": 4444,
            },
        ),
        Finding(
            type="dga_domain", value="random.pwned.se",
            confidence=0.6, evidence={"label": "random"},
        ),
    ]
    iocs = collect_iocs_from_findings(findings)
    types = {t for (t, v) in iocs}
    values = {v for (t, v) in iocs}

    assert "ip" in types
    assert "domain" in types
    assert "1.2.3.4" in values
    assert "random.pwned.se" in values


def test_collect_iocs_dedup():
    """Один IP в двух findings — один IOC."""
    from paradox.models import Finding

    findings = [
        Finding(type="a", value="x", confidence=0.5,
                evidence={"dst_ip": "8.8.8.8"}),
        Finding(type="b", value="y", confidence=0.5,
                evidence={"dst_ip": "8.8.8.8"}),
    ]
    iocs = collect_iocs_from_findings(findings)
    assert iocs.count(("ip", "8.8.8.8")) == 1