"""Тесты ThreatFoxEnricher."""
from paradox.integrations.threatfox import ThreatFoxEnricher


def test_disabled_without_key(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    e = ThreatFoxEnricher(auth_key=None)
    assert not e.enabled


def test_supports_ip_domain_hash():
    assert set(ThreatFoxEnricher(auth_key="x").supports) == {"ip", "domain", "hash"}


def test_lookup_success(monkeypatch):
    e = ThreatFoxEnricher(auth_key="x")
    monkeypatch.setattr(e, "_fetch", lambda i, t: (
        {"query_status": "ok", "data": [{"ioc": i}]}, None,
    ))
    r = e.lookup("1.2.3.4", "ip")
    assert r.ok
    assert r.data["query_status"] == "ok"


def test_lookup_no_result(monkeypatch):
    e = ThreatFoxEnricher(auth_key="x")
    monkeypatch.setattr(e, "_fetch", lambda i, t: (None, None))
    r = e.lookup("1.2.3.4", "ip")
    assert r.ok
    assert r.data == {}
