"""Тесты парсера X.509 Certificate на синтетических мини-сертификатах."""
import pytest

from pcap_triage.x509_der import DerError
from pcap_triage.x509_cert import parse_certificate


# === Хелперы для сборки TLV ===

def _tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    if n < 0x100:
        return bytes([tag, 0x81, n]) + value
    return bytes([tag, 0x82, (n >> 8) & 0xFF, n & 0xFF]) + value


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(parts))


def _int(n: int) -> bytes:
    if n == 0:
        return bytes([0x02, 0x01, 0x00])
    length = (n.bit_length() + 7) // 8
    return bytes([0x02, length]) + n.to_bytes(length, "big")


def _null() -> bytes:
    return bytes([0x05, 0x00])


def _oid(arcs_str: str) -> bytes:
    parts = [int(x) for x in arcs_str.split(".")]
    first = parts[0] * 40 + parts[1]
    data = bytes([first])
    for arc in parts[2:]:
        if arc < 0x80:
            data += bytes([arc])
        else:
            buf = []
            while arc > 0x7F:
                buf.append((arc & 0x7F) | 0x80)
                arc >>= 7
            buf.append(arc)
            data += bytes(reversed(buf))
    return bytes([0x06, len(data)]) + data


def _printable(s: str) -> bytes:
    b = s.encode("ascii")
    return bytes([0x13, len(b)]) + b


def _utctime(s: str) -> bytes:
    b = s.encode("ascii")
    return bytes([0x17, len(b)]) + b


def _octet(b: bytes) -> bytes:
    return bytes([0x04, len(b)]) + b


def _ctx(num: int, value: bytes, constructed: bool = False) -> bytes:
    tag = 0x80 | (num & 0x1F)
    if constructed:
        tag |= 0x20
    return _tlv(tag, value)


def _rdn(cn: str) -> bytes:
    return _set(_seq(_oid("2.5.4.3"), _printable(cn)))


def _name(cn: str) -> bytes:
    return _seq(_rdn(cn))


def _validity(nb: str, na: str) -> bytes:
    return _seq(_utctime(nb), _utctime(na))


def _san_ext(dns: tuple, ips: tuple) -> bytes:
    """Extensions [3] c одним SAN."""
    gn = b""
    for d in dns:
        gn += _ctx(2, d.encode("ascii"))
    for ip in ips:
        gn += _ctx(7, ip)
    san_inner = _seq(gn)
    ext = _seq(_oid("2.5.29.17"), _octet(san_inner))
    return _seq(ext)  # SEQUENCE OF Extension


def _cert(
    subject_cn: str,
    issuer_cn: str,
    nb: str = "240101000000Z",
    na: str = "251231235959Z",
    san_dns: tuple = (),
    san_ips: tuple = (),
    include_version: bool = True,
) -> bytes:
    parts = []
    if include_version:
        parts.append(_ctx(0, _int(2), constructed=True))
    parts.append(_int(12345))                                        # serial
    parts.append(_seq(_oid("1.2.840.113549.1.1.11"), _null()))       # sigAlg
    parts.append(_name(issuer_cn))                                   # issuer
    parts.append(_validity(nb, na))                                  # validity
    parts.append(_name(subject_cn))                                  # subject
    parts.append(_seq(                                                # SPKI-заглушка
        _seq(_oid("1.2.840.113549.1.1.1"), _null()),
        _tlv(0x03, b"\x00" + b"\x00" * 4),
    ))
    if san_dns or san_ips:
        parts.append(_ctx(3, _san_ext(san_dns, san_ips), constructed=True))

    tbs = _seq(*parts)
    return _seq(
        tbs,
        _seq(_oid("1.2.840.113549.1.1.11"), _null()),
        _tlv(0x03, b"\x00" + b"\x00" * 8),
    )


# === Тесты ===

def test_parse_simple_v3():
    der = _cert("example.com", "Test CA")
    cert = parse_certificate(der)
    assert cert.subject_cn == "example.com"
    assert cert.issuer_cn == "Test CA"
    assert cert.is_self_signed is False
    assert cert.not_before == "2024-01-01T00:00:00"
    assert cert.not_after == "2025-12-31T23:59:59"
    assert cert.san_dns == []
    assert cert.san_ips == []


def test_v1_cert_without_version():
    der = _cert("example.com", "Test CA", include_version=False)
    cert = parse_certificate(der)
    assert cert.subject_cn == "example.com"
    assert cert.issuer_cn == "Test CA"


def test_self_signed_detected():
    der = _cert("example.com", "example.com")
    cert = parse_certificate(der)
    assert cert.is_self_signed is True


def test_self_signed_false():
    der = _cert("example.com", "Test CA")
    cert = parse_certificate(der)
    assert cert.is_self_signed is False


def test_san_dns_only():
    der = _cert(
        "example.com", "Test CA",
        san_dns=("example.com", "www.example.com"),
    )
    cert = parse_certificate(der)
    assert cert.san_dns == ["example.com", "www.example.com"]
    assert cert.san_ips == []


def test_san_ips_only():
    der = _cert(
        "example.com", "Test CA",
        san_ips=(b"\x01\x02\x03\x04", b"\x0A\x00\x00\x01"),
    )
    cert = parse_certificate(der)
    assert cert.san_ips == ["1.2.3.4", "10.0.0.1"]


def test_san_mixed():
    der = _cert(
        "example.com", "Test CA",
        san_dns=("a.example",),
        san_ips=(b"\x7F\x00\x00\x01",),
    )
    cert = parse_certificate(der)
    assert cert.san_dns == ["a.example"]
    assert cert.san_ips == ["127.0.0.1"]


def test_no_san_no_extensions():
    der = _cert("example.com", "Test CA")
    cert = parse_certificate(der)
    assert cert.san_dns == []
    assert cert.san_ips == []


def test_broken_der_raises():
    with pytest.raises(DerError):
        parse_certificate(b"\x00\x01\x02")


def test_empty_der_raises():
    with pytest.raises(DerError):
        parse_certificate(b"")


def test_truncated_certificate_raises():
    der = _cert("example.com", "Test CA")
    # Обрезаем — length не сойдётся
    with pytest.raises(DerError):
        parse_certificate(der[:-20])
