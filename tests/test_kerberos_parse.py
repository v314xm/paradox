"""Тесты парсера Kerberos (ASN.1 DER).

Валидный AS-REQ, собранный вручную по RFC 4120:
  cname  = test          (PrincipalName, NT-PRINCIPAL)
  realm  = EXAMPLE.COM   (GeneralString)
  sname  = krbtgt        (PrincipalName)
"""
from paradox.kerberos_parse import parse_kerberos


# [APPLICATION 10] SEQUENCE {
#   [1] pvno = 5,
#   [2] msg-type = 10 (AS-REQ),
#   [4] KDC-REQ-BODY {
#       [0] kdc-options,
#       [1] cname "test",
#       [2] realm "EXAMPLE.COM",
#       [3] sname "krbtgt",
#       [5] till "20200101000000Z",
#       [7] nonce 0x123456,
#       [8] etype [23]
#   }
# }
AS_REQ_HEX = (
    "6a723070"
    "a103020105"
    "a20302010a"
    "a4643062"
    "a00703050040810010"
    "a111300fa003020101a10830061b0474657374"
    "a20d1b0b4558414d504c452e434f4d"
    "a3133011a003020101a10a30081b066b7262746774"
    "a511180f32303230303130313030303030305a"
    "a7050203123456"
    "a806300402020017"
)


def test_parse_as_req():
    """AS-REQ: извлекаются msg_type, cname, realm, sname."""
    info = parse_kerberos(bytes.fromhex(AS_REQ_HEX))

    assert info is not None
    assert info.msg_type == 10
    assert info.cname == "test"
    assert info.realm == "EXAMPLE.COM"
    assert info.sname == "krbtgt"


def test_parse_empty():
    """Пустой / мусорный payload — возвращаем None, не падаем."""
    assert parse_kerberos(b"") is None
    assert parse_kerberos(b"\x00") is None
    assert parse_kerberos(b"\xff\xff\xff\xff") is None


def test_parse_random_bytes():
    """Случайные байты — не падаем с исключением."""
    parse_kerberos(b"\x6a\x81\x80" + b"\x00" * 128)
    parse_kerberos(b"\x30\x0f\x02\x01\x05\xa0\x0a\x30\x08")


def test_parse_tcp_prefix():
    """TCP: 4 байта длины перед ASN.1 — не мешают."""
    raw = bytes.fromhex(AS_REQ_HEX)
    tcp_payload = len(raw).to_bytes(4, "big") + raw

    info = parse_kerberos(tcp_payload)
    assert info is not None
    assert info.msg_type == 10
    assert info.cname == "test"
    assert info.realm == "EXAMPLE.COM"


def test_parse_truncated():
    """Обрезанный AS-REQ — не падаем, отдаём частичное или None."""
    raw = bytes.fromhex(AS_REQ_HEX)
    info = parse_kerberos(raw[:60])
    assert info is None or info.msg_type == 10
