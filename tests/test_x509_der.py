"""Тесты минимального DER-парсера."""
import pytest

from pcap_triage.x509_der import (
    DerError,
    TAG_INTEGER,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_UTF8_STRING,
    as_int,
    as_oid,
    as_str,
    as_time,
    parse_der,
)


# === Базовый разбор ===

def test_parse_simple_sequence():
    # SEQUENCE { INTEGER 5 }
    # 30 03 02 01 05
    data = bytes.fromhex("3003020105")
    node = parse_der(data)
    assert node.tag == TAG_SEQUENCE
    assert node.constructed is True
    assert node.tag_class == 0
    assert len(node.children) == 1
    assert node.children[0].tag == TAG_INTEGER
    assert node.children[0].value == b"\x05"


def test_parse_empty_sequence():
    # SEQUENCE {} = 30 00
    data = bytes.fromhex("3000")
    node = parse_der(data)
    assert node.tag == TAG_SEQUENCE
    assert node.children == []
    assert node.value == b""


def test_parse_nested_sequence():
    # SEQUENCE { SEQUENCE { INTEGER 1 } INTEGER 2 }
    # 30 07  30 03 02 01 01  02 01 02
    data = bytes.fromhex("30083003020101020102")
    node = parse_der(data)
    assert node.tag == TAG_SEQUENCE
    assert len(node.children) == 2
    assert node.children[0].tag == TAG_SEQUENCE
    assert node.children[1].tag == TAG_INTEGER


def test_parse_long_form_length():
    # SEQUENCE длиной 130 байт (long form: 81 82)
    # value = 130 байт нулей
    value = b"\x00" * 130
    data = b"\x30\x81\x82" + value
    node = parse_der(data)
    assert node.tag == TAG_SEQUENCE
    assert len(node.value) == 130


def test_parse_long_form_2byte():
    # SEQUENCE длиной 500 (82 01 F4)
    value = b"\x00" * 500
    data = b"\x30\x82\x01\xF4" + value
    node = parse_der(data)
    assert len(node.value) == 500


# === INTEGER ===

def test_as_int_positive():
    node = parse_der(bytes.fromhex("020105"))
    assert as_int(node) == 5


def test_as_int_zero():
    node = parse_der(bytes.fromhex("020100"))
    assert as_int(node) == 0


def test_as_int_large():
    # INTEGER 256 = 02 02 01 00
    node = parse_der(bytes.fromhex("02020100"))
    assert as_int(node) == 256


def test_as_int_negative():
    # INTEGER -1 = 02 01 FF (two's complement)
    node = parse_der(bytes.fromhex("0201FF"))
    assert as_int(node) == -1


def test_as_int_wrong_tag():
    node = parse_der(bytes.fromhex("06012A"))
    with pytest.raises(DerError):
        as_int(node)


# === OID ===

def test_as_oid_common():
    # OID 2.5.29.17 (subjectAltName) = 06 03 55 1D 11
    node = parse_der(bytes.fromhex("0603551D11"))
    assert as_oid(node) == "2.5.29.17"


def test_as_oid_short():
    # OID 1.2.840.113549.1.1.11 (sha256WithRSA)
    # 06 09 2A 86 48 86 F7 0D 01 01 0B
    node = parse_der(bytes.fromhex("06092A864886F70D01010B"))
    assert as_oid(node) == "1.2.840.113549.1.1.11"




def test_as_oid_empty_raises():
    node = parse_der(bytes.fromhex("0600"))
    with pytest.raises(DerError):
        as_oid(node)


# === Строки ===

def test_as_str_utf8():
    # UTF8String "hi" = 0C 02 68 69
    node = parse_der(bytes.fromhex("0C026869"))
    assert as_str(node) == "hi"


def test_as_str_printable():
    # PrintableString "CN" = 13 02 43 4E
    node = parse_der(bytes.fromhex("1302434E"))
    assert as_str(node) == "CN"


def test_as_str_ia5():
    # IA5String "a@b" = 16 03 61 40 62
    node = parse_der(bytes.fromhex("1603614062"))
    assert as_str(node) == "a@b"


def test_as_str_wrong_tag():
    node = parse_der(bytes.fromhex("020105"))
    with pytest.raises(DerError):
        as_str(node)


# === Время ===

def test_as_time_utc():
    # UTCTime "240101120000Z" = 17 0D 32 34 30 31 30 31 31 32 30 30 30 30 5A
    hex_str = "170D32343031303131323 03030305A".replace(" ", "")
    node = parse_der(bytes.fromhex(hex_str))
    result = as_time(node)
    assert result is not None
    iso, kind = result
    assert kind == "utc"
    assert iso.startswith("2024-01-01T12:00:00")


def test_as_time_utc_1950s():
    # UTCTime "500101000000Z" -> 1950-01-01
    hex_str = "170D3530303130313030303030305A"
    node = parse_der(bytes.fromhex(hex_str))
    result = as_time(node)
    assert result is not None
    iso, _ = result
    assert iso.startswith("1950-01-01")


def test_as_time_generalized():
    # GeneralizedTime "20240101120000Z" (15 символов + Z = 15)
    # 18 0F 32 30 32 34 30 31 30 31 31 32 30 30 30 30 5A
    hex_str = "180F32303234303130313132303030305A"
    node = parse_der(bytes.fromhex(hex_str))
    result = as_time(node)
    assert result is not None
    iso, kind = result
    assert kind == "generalized"
    assert iso.startswith("2024-01-01T12:00:00")


def test_as_time_wrong_tag():
    node = parse_der(bytes.fromhex("020105"))
    assert as_time(node) is None


# === Ошибки ===

def test_truncated_value_raises():
    # SEQUENCE заявляет 10 байт, реально 3
    data = bytes.fromhex("300A0201 05".replace(" ", ""))
    with pytest.raises(DerError):
        parse_der(data)


def test_indefinite_length_raises():
    # 30 80 ... — indefinite, запрещён в DER
    data = bytes.fromhex("3080020105")
    with pytest.raises(DerError):
        parse_der(data)


def test_empty_data_raises():
    with pytest.raises(DerError):
        parse_der(b"")


def test_high_tag_raises():
    # tag 0x1F — high-tag-number form
    data = bytes.fromhex("1F0105")
    with pytest.raises(DerError):
        parse_der(data)
