"""Тесты ProviderCard (offscreen)."""
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from pcap_triage.integrations.base import EnrichmentResult


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _ok(source, data):
    return EnrichmentResult(
        source=source, ioc="8.8.8.8", ioc_type="ip",
        data=data, fetched_at=time.time(), ttl_days=1,
    )


def _err(source, error):
    return EnrichmentResult(
        source=source, ioc="8.8.8.8", ioc_type="ip",
        error=error, fetched_at=time.time(), ttl_days=1,
    )


def test_card_builds_clean(qapp):
    from pcap_triage_gui.widgets.provider_card import ProviderCard
    res = _ok("shodan_internetdb", {"ports": [53], "hostnames": ["dns.google"]})
    c = ProviderCard("shodan_internetdb", res, "8.8.8.8", "ip")
    assert c is not None


def test_card_builds_error(qapp):
    from pcap_triage_gui.widgets.provider_card import ProviderCard
    res = _err("abuseipdb", "rate limited (429)")
    c = ProviderCard("abuseipdb", res, "8.8.8.8", "ip")
    assert c is not None


def test_verdict_abuseipdb_clean(qapp):
    from pcap_triage_gui.widgets.provider_card import _verdict
    assert _verdict("abuseipdb", {"abuseConfidenceScore": 0}, None) == "clean"


def test_verdict_abuseipdb_bad(qapp):
    from pcap_triage_gui.widgets.provider_card import _verdict
    assert _verdict("abuseipdb", {"abuseConfidenceScore": 80}, None) == "bad"


def test_verdict_virustotal_bad(qapp):
    from pcap_triage_gui.widgets.provider_card import _verdict
    data = {"data": {"attributes": {"last_analysis_stats": {"malicious": 10}}}}
    assert _verdict("virustotal", data, None) == "bad"


def test_verdict_error(qapp):
    from pcap_triage_gui.widgets.provider_card import _verdict
    assert _verdict("x", None, "error msg") == "error"


def test_verdict_empty(qapp):
    from pcap_triage_gui.widgets.provider_card import _verdict
    assert _verdict("x", {}, None) == "empty"


def test_short_summary_abuseipdb(qapp):
    from pcap_triage_gui.widgets.provider_card import _short_summary
    s = _short_summary("abuseipdb", {"abuseConfidenceScore": 5, "isp": "X"}, None, "ip")
    assert "5/100" in s
