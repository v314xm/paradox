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
    args, kwargs = mock_parse.call_args
    assert args == (b"FAKE_TLS_STREAM",)
    assert callable(kwargs["on_der_error"])


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


class _FakeCert:
    subject_cn = "example.com"
    issuer_cn = "Example CA"
    not_before = "2025-01-01T00:00:00"
    not_after = "2026-01-01T00:00:00"


def test_repeated_connections_keep_one_cert():
    """10 сессий к одному серверу → один сертификат, не 10."""
    state = CaptureState()
    for sport in range(50000, 50010):
        key = FlowKey("tcp", "10.0.0.5", "1.1.1.1", sport, 443)
        state.flows[key] = _make_flow(sni="example.com")
        state.tcp_streams[
            FlowKey("tcp", "1.1.1.1", "10.0.0.5", 443, sport)
        ] = b"TLS"

    with patch(
        "paradox.extractors.tls_cert.parse_certificate_from_stream",
        return_value=_FakeCert(),
    ):
        TlsCertificateExtractor().run_post_extract(state, config=None)

    assert len(state.tls_certs) == 1


def test_two_clients_keep_two_certs():
    """Разные клиенты — разные finding'и, дедуп по серверу их не съедает."""
    state = CaptureState()
    for src, sport in (("10.0.0.5", 50000), ("10.0.0.6", 50001)):
        key = FlowKey("tcp", src, "1.1.1.1", sport, 443)
        state.flows[key] = _make_flow(sni="example.com")
        state.tcp_streams[
            FlowKey("tcp", "1.1.1.1", src, 443, sport)
        ] = b"TLS"

    with patch(
        "paradox.extractors.tls_cert.parse_certificate_from_stream",
        return_value=_FakeCert(),
    ):
        TlsCertificateExtractor().run_post_extract(state, config=None)

    assert len(state.tls_certs) == 2


def test_der_errors_are_counted_in_state():
    """Ошибки разбора DER попадают в state, а не глотаются."""
    state = CaptureState()
    key = FlowKey("tcp", "10.0.0.5", "1.1.1.1", 50000, 443)
    state.flows[key] = _make_flow(sni="example.com")
    state.tcp_streams[
        FlowKey("tcp", "1.1.1.1", "10.0.0.5", 443, 50000)
    ] = b"BROKEN_TLS"

    def _fake_parse(stream, on_der_error=None):
        on_der_error()
        on_der_error()
        return None

    with patch(
        "paradox.extractors.tls_cert.parse_certificate_from_stream",
        side_effect=_fake_parse,
    ):
        TlsCertificateExtractor().run_post_extract(state, config=None)

    assert state.tls_certs == []
    assert state.tls_cert_parse_errors == 2
