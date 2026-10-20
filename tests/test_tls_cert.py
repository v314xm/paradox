"""Тесты парсера TLS Certificate handshake."""
from paradox.tls_cert import parse_certificate_from_stream
from tests.test_x509_cert import (
    _cert,
    _ctx,
    _int,
    _null,
    _oid,
    _octet,
    _seq,
    _tlv,
)


def _tls_record(handshake_bytes: bytes) -> bytes:
    """Обернуть handshake-байты в TLS record (content_type=0x16)."""
    length = len(handshake_bytes)
    return (
        bytes([0x16, 0x03, 0x03, (length >> 8) & 0xFF, length & 0xFF])
        + handshake_bytes
    )


def _handshake_message(hs_type: int, body: bytes) -> bytes:
    """Обернуть body в TLS handshake message."""
    n = len(body)
    return (
        bytes([hs_type, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
        + body
    )


def _certificate_body_tls12(cert_der: bytes) -> bytes:
    """Certificate body в формате TLS 1.2."""
    cert_len = len(cert_der)
    chain = (cert_len.to_bytes(3, "big") + cert_der)
    return len(chain).to_bytes(3, "big") + chain


def _certificate_body_tls13(cert_der: bytes) -> bytes:
    """Certificate body в формате TLS 1.3 (пустой request_context)."""
    cert_len = len(cert_der)
    chain = (cert_len.to_bytes(3, "big") + cert_der)
    return (
        b"\x00"
        + len(chain).to_bytes(3, "big")
        + chain
        + b"\x00\x00"
    )


def _stream_with_certificate(cert_der: bytes, tls13: bool = False) -> bytes:
    """Полный TCP-поток: ServerHello + Certificate."""
    server_hello = _handshake_message(2, b"")
    if tls13:
        body = _certificate_body_tls13(cert_der)
    else:
        body = _certificate_body_tls12(cert_der)
    cert_msg = _handshake_message(11, body)
    return _tls_record(server_hello) + _tls_record(cert_msg)


def test_parse_tls12_certificate():
    der = _cert("example.com", "Test CA")
    stream = _stream_with_certificate(der, tls13=False)
    cert = parse_certificate_from_stream(stream)
    assert cert is not None
    assert cert.subject_cn == "example.com"
    assert cert.issuer_cn == "Test CA"


def test_parse_tls13_certificate():
    der = _cert("example.com", "Test CA")
    stream = _stream_with_certificate(der, tls13=True)
    cert = parse_certificate_from_stream(stream)
    assert cert is not None
    assert cert.subject_cn == "example.com"


def test_parse_cert_with_san():
    der = _cert(
        "example.com", "Test CA",
        san_dns=("example.com", "www.example.com"),
    )
    stream = _stream_with_certificate(der)
    cert = parse_certificate_from_stream(stream)
    assert cert is not None
    assert cert.san_dns == ["example.com", "www.example.com"]


def test_empty_stream():
    assert parse_certificate_from_stream(b"") is None


def test_non_tls_stream():
    assert parse_certificate_from_stream(b"GET / HTTP/1.1\r\n") is None


def test_truncated_record():
    der = _cert("example.com", "Test CA")
    stream = _stream_with_certificate(der)
    assert parse_certificate_from_stream(stream[:20]) is None


def test_no_certificate_message():
    server_hello = _handshake_message(2, b"")
    stream = _tls_record(server_hello)
    assert parse_certificate_from_stream(stream) is None


def test_two_handshake_in_one_record():
    der = _cert("example.com", "Test CA")
    sh = _handshake_message(2, b"")
    cm = _handshake_message(11, _certificate_body_tls12(der))
    stream = _tls_record(sh + cm)
    cert = parse_certificate_from_stream(stream)
    assert cert is not None
    assert cert.subject_cn == "example.com"
