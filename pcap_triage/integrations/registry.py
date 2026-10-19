"""Реестр enrichment-провайдеров.

Единственный источник правды: какой провайдер под каким именем.
pipeline.build_default_orchestrator берёт отсюда, фильтрует по
config.enrichment_enabled_providers.
"""
from __future__ import annotations

from pcap_triage.integrations.abuseipdb import AbuseIPDBEnricher
from pcap_triage.integrations.alienvault_otx import AlienVaultOTXEnricher
from pcap_triage.integrations.greynoise import GreyNoiseEnricher
from pcap_triage.integrations.malwarebazaar import MalwareBazaarEnricher
from pcap_triage.integrations.shodan_internetdb import ShodanInternetDBEnricher
from pcap_triage.integrations.threatfox import ThreatFoxEnricher
from pcap_triage.integrations.urlhaus import URLhausEnricher
from pcap_triage.integrations.urlscan import URLScanEnricher
from pcap_triage.integrations.virustotal import VirusTotalEnricher

#: name -> класс провайдера. Имена совпадают с ключами
#: Config.enrichment_enabled_providers.
REGISTRY: dict[str, type] = {
    "shodan_internetdb": ShodanInternetDBEnricher,
    "abuseipdb": AbuseIPDBEnricher,
    "virustotal": VirusTotalEnricher,
    "greynoise": GreyNoiseEnricher,
    "alienvault_otx": AlienVaultOTXEnricher,
    "urlscan": URLScanEnricher,
    # Требуют ABUSECH_AUTH_KEY — включаются вручную.
    "urlhaus": URLhausEnricher,
    "malwarebazaar": MalwareBazaarEnricher,
    "threatfox": ThreatFoxEnricher,
}


def get_provider(name: str):
    """Класс провайдера по имени или None."""
    return REGISTRY.get(name)


def list_providers() -> list[str]:
    """Имена всех известных провайдеров (не только включённых)."""
    return sorted(REGISTRY.keys())
