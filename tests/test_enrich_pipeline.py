"""
Тесты attach_enrichment_to_findings и enrich_findings (без сети).
"""
import time
from dataclasses import replace

from paradox.config import Config
from paradox.integrations.base import EnrichmentResult
from paradox.integrations.pipeline import (
    attach_enrichment_to_findings,
)
from paradox.models import Finding


def test_attach_enrichment_to_ip_finding():
    """dst_ip → evidence["enrichment"]["8.8.8.8"]["shodan_internetdb"]."""
    findings = [
        Finding(
            type="suspicious_port", value="8.8.8.8:4444",
            confidence=0.5, evidence={"dst_ip": "8.8.8.8"},
        ),
    ]
    enrichment_map = {
        ("ip", "8.8.8.8"): [
            EnrichmentResult(
                source="shodan_internetdb", ioc="8.8.8.8", ioc_type="ip",
                data={"ports": [53, 443]},
                fetched_at=time.time(), ttl_days=7,
            ),
        ],
    }

    attach_enrichment_to_findings(findings, enrichment_map)

    ev = findings[0].evidence["enrichment"]
    assert "8.8.8.8" in ev
    assert ev["8.8.8.8"]["shodan_internetdb"]["ports"] == [53, 443]


def test_attach_enrichment_skips_errors():
    """Ошибочный EnrichmentResult не прикрепляется."""
    findings = [
        Finding(type="x", value="8.8.8.8", confidence=0.5,
                evidence={"dst_ip": "8.8.8.8"}),
    ]
    enrichment_map = {
        ("ip", "8.8.8.8"): [
            EnrichmentResult(
                source="shodan_internetdb", ioc="8.8.8.8", ioc_type="ip",
                error="timeout",
                fetched_at=time.time(), ttl_days=7,
            ),
        ],
    }

    attach_enrichment_to_findings(findings, enrichment_map)

    assert "enrichment" not in findings[0].evidence


def test_attach_enrichment_no_matching_iocs():
    """Если в map ничего нет — evidence не меняется."""
    findings = [
        Finding(type="x", value="1.2.3.4", confidence=0.5,
                evidence={"dst_ip": "1.2.3.4"}),
    ]
    attach_enrichment_to_findings(findings, {})
    assert "enrichment" not in findings[0].evidence


def test_attach_enrichment_multiple_sources():
    """Два провайдера на один IP — оба в evidence."""
    findings = [
        Finding(type="x", value="8.8.8.8", confidence=0.5,
                evidence={"dst_ip": "8.8.8.8"}),
    ]
    enrichment_map = {
        ("ip", "8.8.8.8"): [
            EnrichmentResult(
                source="shodan_internetdb", ioc="8.8.8.8", ioc_type="ip",
                data={"ports": [53]},
                fetched_at=time.time(), ttl_days=7,
            ),
            EnrichmentResult(
                source="virustotal", ioc="8.8.8.8", ioc_type="ip",
                data={"malicious": 0, "harmless": 70},
                fetched_at=time.time(), ttl_days=7,
            ),
        ],
    }

    attach_enrichment_to_findings(findings, enrichment_map)

    ev = findings[0].evidence["enrichment"]["8.8.8.8"]
    assert "shodan_internetdb" in ev
    assert "virustotal" in ev