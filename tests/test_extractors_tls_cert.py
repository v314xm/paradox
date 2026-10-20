"""Тесты TlsCertificateExtractor.

Проверяем обход flows и сборку state.tls_certs. Парсинг X.509
мокаем — он уже покрыт отдельными тестами в test_x509_cert.py
и test_tls_cert.py.
"""
from unittest.mock import patch

from paradox.extractors.tls_cert import TlsCertificateExtractor
from paradox.models import CaptureState, FlowKey, FlowStats


def _make_flow(sni: str | None = None) -> FlowStats:
    f = FlowStats()
    f.sni = sni
    return f


def test_tls_cert_extractor_happy_path():
    """Есть SNI + обратный поток → сертификат извлекается и сохраняется."""
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "1.1.1.1", 54321, 443)
    state.flows[key] = _make_flow(sni="example.com")

    reverse_key = FlowKey("tcp", "1.1.1.1", "10.0.0.5", 443, 54321)
    state.tcp_streams[reverse_key] = b"FAKE_TLS_STREAM"

    fake_cert = object()

    with patch(
        "paradox.extractors.tls_cert.parse_certificate_from_stream",
        return_value=fake_cert,
    ) as mock_parse:
        TlsCertificateExtractor().run_post_extract(state, config=None)

    assert len(state.tls_certs) == 1
    assert state.tls_certs[0] == (key, fake_cert)
    mock_parse.assert_called_once_with(b"FAKE_TLS_STREAM")


def test_tls_cert_extractor_no_sni():
    """Flow без SNI → пропускается, парсер не вызывается."""
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "1.1.1.1", 54321, 443)
    state.flows[key] = _make_flow(sni=None)

    with patch(
        "paradox.extractors.tls_cert.parse_certificate_from_stream",
    ) as mock_parse:
        TlsCertificateExtractor().run_post_extract(state, config=None)

    assert state.tls_certs == []
    mock_parse.assert_not_called()


def test_tls_cert_extractor_no_reverse_stream():
    """SNI есть, но обратного потока в tcp_streams нет → пропускаем."""
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "1.1.1.1", 54321, 443)
    state.flows[key] = _make_flow(sni="example.com")
    # Обратного потока нет

    with patch(
        "paradox.extractors.tls_cert.parse_certificate_from_stream",
    ) as mock_parse:
        TlsCertificateExtractor().run_post_extract(state, config=None)

    assert state.tls_certs == []
    mock_parse.assert_not_called()


def test_tls_cert_extractor_parse_fails():
    """Парсер вернул None → не падаем, ничего не сохраняем."""
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "1.1.1.1", 54321, 443)
    state.flows[key] = _make_flow(sni="example.com")

    reverse_key = FlowKey("tcp", "1.1.1.1", "10.0.0.5", 443, 54321)
    state.tcp_streams[reverse_key] = b"BAD_BYTES"

    with patch(
        "paradox.extractors.tls_cert.parse_certificate_from_stream",
        return_value=None,
    ):
        TlsCertificateExtractor().run_post_extract(state, config=None)

    assert state.tls_certs == []
