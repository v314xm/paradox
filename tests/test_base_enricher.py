"""Тесты базового класса enrichment-провайдеров."""
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from paradox.integrations.base_enricher import BaseEnricher


class DummyEnricher(BaseEnricher):
    name = "dummy"
    supports = ("ip", "domain")
    ttl_days = 7
    ttl_days_negative = 1

    def __init__(self, mock_response=None, mock_error=None):
        self._mock_response = mock_response
        self._mock_error = mock_error

    def _fetch(self, ioc, ioc_type):
        if self._mock_error is not None:
            return None, self._mock_error
        return self._mock_response, None


@pytest.fixture
def mock_urlopen():
    with patch("urllib.request.urlopen") as mock:
        yield mock


def test_http_get_json_success(mock_urlopen):
    """200 OK → JSON разбирается в dict."""
    resp = MagicMock()
    resp.read.return_value = b'{"key": "value"}'
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=None)
    mock_urlopen.return_value = resp

    e = DummyEnricher()
    data, error = e._http_get_json("https://example.com/api")
    assert data == {"key": "value"}
    assert error is None


def test_http_get_json_404(mock_urlopen):
    """404 → спец-сигнал __not_found__."""
    mock_urlopen.side_effect = HTTPError(
        url="https://example.com", code=404, msg="Not Found", hdrs={}, fp=None
    )
    e = DummyEnricher()
    data, error = e._http_get_json("https://example.com/api")
    assert data is None
    assert error == "__not_found__"


def test_http_get_json_401(mock_urlopen):
    """401 → сообщение про ключ."""
    mock_urlopen.side_effect = HTTPError(
        url="https://example.com", code=401, msg="Unauthorized", hdrs={}, fp=None
    )
    e = DummyEnricher()
    _, error = e._http_get_json("https://example.com/api")
    assert "unauthorized" in error.lower()


def test_http_get_json_429(mock_urlopen):
    """429 → rate limited."""
    mock_urlopen.side_effect = HTTPError(
        url="https://example.com", code=429, msg="Too Many Requests", hdrs={}, fp=None
    )
    e = DummyEnricher()
    _, error = e._http_get_json("https://example.com/api")
    assert "rate limited" in error.lower()


def test_http_get_json_500(mock_urlopen):
    """5xx → server error."""
    mock_urlopen.side_effect = HTTPError(
        url="https://example.com", code=503, msg="Service Unavailable", hdrs={}, fp=None
    )
    e = DummyEnricher()
    _, error = e._http_get_json("https://example.com/api")
    assert "server error" in error.lower()


def test_resolve_not_found():
    """__not_found__ превращается в (None, None)."""
    e = DummyEnricher()
    data, error = e._resolve_not_found(None, "__not_found__")
    assert data is None
    assert error is None


def test_lookup_unsupported_type():
    """Тип не поддерживается → ошибка, а не запрос."""
    e = DummyEnricher()
    result = e.lookup("value", "hash")  # DummyEnricher не поддерживает hash
    assert not result.ok
    assert "unsupported ioc_type" in result.error


def test_lookup_negative_caching():
    """404 → пустой result, но TTL = ttl_days_negative."""
    e = DummyEnricher()
    e._mock_response = None  # 404 → data=None
    # Наследуем базовый lookup: он с ttl_days_negative для пустых
    result = e.lookup("8.8.8.8", "ip")
    assert result.ok
    assert result.data == {}
    assert result.ttl_days == e.ttl_days_negative