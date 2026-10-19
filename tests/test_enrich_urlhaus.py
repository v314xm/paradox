"""Тесты URLhausEnricher."""
from pcap_triage.integrations.urlhaus import URLhausEnricher


def test_disabled_without_key(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    e = URLhausEnricher(auth_key=None)
    assert not e.enabled
    r = e.lookup("evil.com", "domain")
    assert not r.ok
    assert "ABUSECH_AUTH_KEY" in r.error


def test_enabled_with_key():
    e = URLhausEnricher(auth_key="fake")
    assert e.enabled


def test_supports_domain_url():
    assert set(URLhausEnricher(auth_key="x").supports) == {"domain", "url"}


def test_lookup_success(monkeypatch):
    e = URLhausEnricher(auth_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda i, t: (
        {"query_status": "ok", "urls": [{"url": "http://evil.com/x"}]}, None,
    ))
    r = e.lookup("evil.com", "domain")
    assert r.ok
    assert r.data["query_status"] == "ok"


def test_lookup_no_results_returns_empty(monkeypatch):
    e = URLhausEnricher(auth_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda i, t: (None, None))
    r = e.lookup("clean.com", "domain")
    assert r.ok
    assert r.data == {}
