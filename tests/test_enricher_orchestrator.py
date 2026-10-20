"""Тесты orchestrator: enabled, категории ошибок, private IP."""
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from paradox.config import Config
from paradox.integrations.base import EnrichmentResult
from paradox.integrations.enricher import (
    EnricherOrchestrator,
    _is_private_ip,
)


# -- private IP ----------------------------------------------------------


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.31.0.1",
    "192.168.1.1",
    "127.0.0.1", "::1",
    "169.254.1.1", "fe80::1",
    "224.0.0.1", "239.0.0.1",
    "100.64.0.1",           # CGNAT
    "0.0.0.0",
    "fc00::1",              # IPv6 ULA
])
def test_private_ip_true(ip):
    assert _is_private_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "8.8.8.8", "1.1.1.1", "2001:4860::8888", "2606:4700::1111",
])
def test_public_ip_false(ip):
    assert _is_private_ip(ip) is False


def test_garbage_ip_is_false():
    assert _is_private_ip("not an ip") is False
    assert _is_private_ip("") is False
    assert _is_private_ip(None) is False


# -- orchestrator: enabled=False не дёргается ----------------------------


@dataclass
class FakeProvider:
    name: str
    supports: tuple
    enabled: bool = True
    calls: int = 0

    def lookup(self, ioc, ioc_type):
        self.calls += 1
        return EnrichmentResult(
            source=self.name, ioc=ioc, ioc_type=ioc_type,
            data={"ok": True}, fetched_at=0.0, ttl_days=1,
        )


class FakeCache:
    def __init__(self):
        self.data = {}

    def get(self, source, ioc):
        return self.data.get((source, ioc))

    def put(self, result):
        self.data[(result.source, result.ioc)] = result

    def close(self):
        pass


def test_disabled_provider_not_called():
    p = FakeProvider(name="x", supports=("ip",), enabled=False)
    orch = EnricherOrchestrator([p], FakeCache(), Config())
    orch.enrich([("ip", "8.8.8.8")])
    assert p.calls == 0
    assert orch.stats["skipped_disabled"] == 1


def test_enabled_provider_called():
    p = FakeProvider(name="shodan_internetdb", supports=("ip",), enabled=True)
    orch = EnricherOrchestrator([p], FakeCache(), Config())
    orch.enrich([("ip", "8.8.8.8")])
    assert p.calls == 1
    assert orch.stats["provider_calls"] == 1


def test_unsupported_skipped():
    """Провайдер, ВКЛЮЧЁННЫЙ в Config, но не поддерживающий тип —
    попадает в skipped_unsupported (не в skipped_disabled).

    Используем malwarebazaar (включён в Config по умолчанию), запрос
    идёт по ip — провайдер поддерживает только hash.
    """
    p = FakeProvider(name="malwarebazaar", supports=("hash",))
    orch = EnricherOrchestrator([p], FakeCache(), Config())
    orch.enrich([("ip", "8.8.8.8")])
    assert p.calls == 0
    assert orch.stats["skipped_unsupported"] == 1
    assert orch.stats["skipped_disabled"] == 0


def test_disabled_outside_config_goes_to_disabled_counter():
    """Провайдер, НЕ включённый в Config — skipped_disabled."""
    p = FakeProvider(name="totally_unknown_provider", supports=("ip",))
    orch = EnricherOrchestrator([p], FakeCache(), Config())
    orch.enrich([("ip", "8.8.8.8")])
    assert p.calls == 0
    assert orch.stats["skipped_disabled"] == 1


def test_stats_has_new_counters():
    p = FakeProvider(name="shodan_internetdb", supports=("ip",))
    orch = EnricherOrchestrator([p], FakeCache(), Config())
    for key in ("errors_network", "errors_auth", "errors_server",
                "skipped_disabled", "skipped_unsupported"):
        assert key in orch.stats


def test_error_categories_network():
    @dataclass
    class P:
        name: str = "greynoise"
        supports: tuple = ("ip",)
        enabled: bool = True

        def lookup(self, ioc, ioc_type):
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                error="URLError: timeout", fetched_at=0.0, ttl_days=1,
            )

    orch = EnricherOrchestrator([P()], FakeCache(), Config())
    orch.enrich([("ip", "8.8.8.8")])
    assert orch.stats["errors"] == 1
    assert orch.stats["errors_network"] == 1


def test_error_categories_auth():
    @dataclass
    class P:
        name: str = "abuseipdb"
        supports: tuple = ("ip",)
        enabled: bool = True

        def lookup(self, ioc, ioc_type):
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                error="unauthorized (401)", fetched_at=0.0, ttl_days=1,
            )

    orch = EnricherOrchestrator([P()], FakeCache(), Config())
    orch.enrich([("ip", "8.8.8.8")])
    assert orch.stats["errors_auth"] == 1


def test_error_categories_server():
    @dataclass
    class P:
        name: str = "virustotal"
        supports: tuple = ("ip",)
        enabled: bool = True

        def lookup(self, ioc, ioc_type):
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                error="server error (503)", fetched_at=0.0, ttl_days=1,
            )

    orch = EnricherOrchestrator([P()], FakeCache(), Config())
    orch.enrich([("ip", "8.8.8.8")])
    assert orch.stats["errors_server"] == 1
