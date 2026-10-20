"""Тесты того, что pipeline уважает Config.enrichment_enabled_providers."""
from dataclasses import replace

from paradox.config import Config
from paradox.integrations.pipeline import build_default_orchestrator


def test_orchestrator_contains_enabled_providers():
    cfg = Config()
    orch = build_default_orchestrator(cfg)
    try:
        names = {p.name for p in orch.providers}
        assert "shodan_internetdb" in names
        assert "abuseipdb" in names
        assert "virustotal" in names
    finally:
        orch.close()


def test_orchestrator_skips_disabled_providers():
    cfg = Config()
    object.__setattr__(
        cfg, "enrichment_enabled_providers",
        frozenset({"shodan_internetdb"}),
    )
    orch = build_default_orchestrator(cfg)
    try:
        names = {p.name for p in orch.providers}
        assert names == {"shodan_internetdb"}
    finally:
        orch.close()


def test_orchestrator_empty_when_nothing_enabled():
    cfg = Config()
    object.__setattr__(cfg, "enrichment_enabled_providers", frozenset())
    orch = build_default_orchestrator(cfg)
    try:
        assert orch.providers == []
    finally:
        orch.close()
