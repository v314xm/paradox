"""Тесты VirusTotalEnricher. HTTP замокан."""
from pcap_triage.integrations.virustotal import VirusTotalEnricher


def test_vt_disabled_without_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    e = VirusTotalEnricher(api_key=None)
    assert not e.enabled
    result = e.lookup("8.8.8.8", "ip")
    assert not result.ok
    assert "not set" in result.error


def test_vt_enabled_with_key():
    e = VirusTotalEnricher(api_key="fake")
    assert e.enabled


def test_vt_lookup_ip_success(monkeypatch):
    e = VirusTotalEnricher(api_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda ioc, t: (
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}},
        None,
    ))
    result = e.lookup("8.8.8.8", "ip")
    assert result.ok
    assert result.source == "virustotal"
    assert "data" in result.data


def test_vt_lookup_domain_supported(monkeypatch):
    e = VirusTotalEnricher(api_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda ioc, t: ({}, None))
    result = e.lookup("evil.com", "domain")
    assert result.ok


def test_vt_lookup_hash_supported(monkeypatch):
    e = VirusTotalEnricher(api_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda ioc, t: ({}, None))
    result = e.lookup("a" * 64, "hash")
    assert result.ok


def test_vt_lookup_unsupported_type():
    e = VirusTotalEnricher(api_key="fake")
    result = e.lookup("1.2.3.4:80", "url")
    assert not result.ok
    assert "unsupported" in result.error


def test_vt_lookup_rate_limited(monkeypatch):
    e = VirusTotalEnricher(api_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda ioc, t: (None, "rate limited (429)"))
    result = e.lookup("8.8.8.8", "ip")
    assert not result.ok
    assert "429" in result.error


def test_vt_lookup_unauthorized(monkeypatch):
    e = VirusTotalEnricher(api_key="bad")
    monkeypatch.setattr(e, "_fetch", lambda ioc, t: (None, "unauthorized (401)"))
    result = e.lookup("8.8.8.8", "ip")
    assert not result.ok
    assert "401" in result.error


def test_vt_ttl_short():
    e = VirusTotalEnricher(api_key="fake")
    assert e.ttl_days == 1


def test_vt_supports_ip_domain_hash():
    e = VirusTotalEnricher(api_key="fake")
    assert set(e.supports) == {"ip", "domain", "hash"}
