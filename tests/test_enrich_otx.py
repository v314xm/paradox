"""Тесты AlienVaultOTXEnricher."""
from paradox.integrations.alienvault_otx import AlienVaultOTXEnricher


def test_supports_ip_domain_hash():
    assert set(AlienVaultOTXEnricher().supports) == {"ip", "domain", "hash"}


def test_no_key_required():
    assert AlienVaultOTXEnricher().enabled


def test_lookup_success(monkeypatch):
    e = AlienVaultOTXEnricher()
    monkeypatch.setattr(e, "_fetch", lambda i, t: (
        {"pulse_info": {"count": 3}}, None,
    ))
    r = e.lookup("evil.com", "domain")
    assert r.ok
    assert r.data["pulse_info"]["count"] == 3


def test_lookup_url_unsupported():
    e = AlienVaultOTXEnricher()
    r = e.lookup("http://evil.com", "url")
    assert not r.ok
    assert "unsupported" in r.error


def test_lookup_not_found(monkeypatch):
    e = AlienVaultOTXEnricher()
    monkeypatch.setattr(e, "_fetch", lambda i, t: (None, None))
    r = e.lookup("1.2.3.4", "ip")
    assert r.ok
