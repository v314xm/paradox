"""
Тесты AbuseIPDBEnricher. HTTP замокан — никакой сети.
"""


from paradox.integrations.abuseipdb import AbuseIPDBEnricher


def test_abuseipdb_disabled_without_key(monkeypatch):
    """Без ключа — провайдер отключён, lookup возвращает ошибку."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    e = AbuseIPDBEnricher(api_key=None)
    assert not e.enabled

    result = e.lookup("8.8.8.8", "ip")
    assert not result.ok
    assert "not set" in result.error


def test_abuseipdb_enabled_with_key():
    """С ключом — провайдер включён."""
    e = AbuseIPDBEnricher(api_key="fake_key_12345")
    assert e.enabled


def test_abuseipdb_lookup_success(monkeypatch):
    """Успешный ответ — data заполнена."""
    e = AbuseIPDBEnricher(api_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda ip: (
        {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "isp": "Google LLC",
            "totalReports": 0,
        },
        None,
    ))
    result = e.lookup("8.8.8.8", "ip")
    assert result.ok
    assert result.source == "abuseipdb"
    assert result.data["abuseConfidenceScore"] == 0
    assert result.data["countryCode"] == "US"


def test_abuseipdb_lookup_rate_limited(monkeypatch):
    """429 — ошибка rate limited."""
    e = AbuseIPDBEnricher(api_key="fake")
    monkeypatch.setattr(e, "_fetch", lambda ip: (None, "rate limited (429)"))
    result = e.lookup("8.8.8.8", "ip")
    assert not result.ok
    assert "429" in result.error


def test_abuseipdb_lookup_unauthorized(monkeypatch):
    """401 — неверный ключ."""
    e = AbuseIPDBEnricher(api_key="bad")
    monkeypatch.setattr(e, "_fetch", lambda ip: (None, "unauthorized (401) — проверь ключ"))
    result = e.lookup("8.8.8.8", "ip")
    assert not result.ok
    assert "401" in result.error


def test_abuseipdb_lookup_unsupported_type():
    """Domain не поддержан."""
    e = AbuseIPDBEnricher(api_key="fake")
    result = e.lookup("example.com", "domain")
    assert not result.ok
    assert "unsupported" in result.error


def test_abuseipdb_ttl_short():
    """TTL AbuseIPDB — 1 день (короче Shodan)."""
    e = AbuseIPDBEnricher(api_key="fake")
    assert e.ttl_days == 1