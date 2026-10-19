"""Тесты URLScanEnricher."""
from pcap_triage.integrations.urlscan import URLScanEnricher


def test_supports_domain_url():
    assert set(URLScanEnricher().supports) == {"domain", "url"}


def test_no_key_required():
    assert URLScanEnricher().enabled


def test_lookup_success(monkeypatch):
    e = URLScanEnricher()
    monkeypatch.setattr(e, "_fetch", lambda i, t: (
        {"results": [{"_id": "abc123", "page": {"url": "http://evil.com"}}]}, None,
    ))
    r = e.lookup("evil.com", "domain")
    assert r.ok
    assert len(r.data["results"]) == 1


def test_lookup_no_results(monkeypatch):
    e = URLScanEnricher()
    monkeypatch.setattr(e, "_fetch", lambda i, t: (None, None))
    r = e.lookup("clean.com", "domain")
    assert r.ok
    assert r.data == {}


def test_lookup_ip_unsupported():
    e = URLScanEnricher()
    r = e.lookup("1.2.3.4", "ip")
    assert not r.ok
    assert "unsupported" in r.error
