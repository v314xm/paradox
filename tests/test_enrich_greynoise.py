"""Тесты GreyNoiseEnricher."""
from paradox.integrations.greynoise import GreyNoiseEnricher


def test_supports_only_ip():
    assert GreyNoiseEnricher().supports == ("ip",)


def test_no_key_required():
    e = GreyNoiseEnricher()
    assert e.enabled


def test_lookup_domain_rejected():
    e = GreyNoiseEnricher()
    r = e.lookup("evil.com", "domain")
    assert not r.ok
    assert "unsupported" in r.error


def test_lookup_success(monkeypatch):
    e = GreyNoiseEnricher()
    monkeypatch.setattr(e, "_fetch", lambda i, t: (
        {"noise": True, "riot": False, "classification": "malicious"}, None,
    ))
    r = e.lookup("1.2.3.4", "ip")
    assert r.ok
    assert r.data["noise"] is True


def test_lookup_not_found(monkeypatch):
    e = GreyNoiseEnricher()
    monkeypatch.setattr(e, "_fetch", lambda i, t: (None, None))
    r = e.lookup("1.2.3.4", "ip")
    assert r.ok
    assert r.data == {}


def test_lookup_error(monkeypatch):
    e = GreyNoiseEnricher()
    monkeypatch.setattr(e, "_fetch", lambda i, t: (None, "rate limited (429)"))
    r = e.lookup("1.2.3.4", "ip")
    assert not r.ok
