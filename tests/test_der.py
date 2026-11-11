"""Общий TLV-ридер: строгий режим для X.509, мягкий — для Kerberos."""
import pytest

from paradox.der import DerError, read_tlv


def test_short_form():
    tag, length, value, next_pos = read_tlv(bytes.fromhex("020105"))

    assert (tag, length, value, next_pos) == (0x02, 1, b"\x05", 3)


def test_long_form():
    tag, length, value, next_pos = read_tlv(
        bytes.fromhex("308103020105"),
    )

    assert (tag, length, value, next_pos) == (
        0x30, 3, bytes.fromhex("020105"), 6,
    )


def test_strict_rejects_truncated_value():
    with pytest.raises(DerError):
        read_tlv(bytes.fromhex("3005020105"))


def test_lenient_truncates_value_to_buffer():
    tag, length, value, next_pos = read_tlv(
        bytes.fromhex("30050201"), strict=False,
    )

    assert (tag, length, value, next_pos) == (0x30, 2, b"\x02\x01", 4)


def test_strict_rejects_truncated_long_form():
    with pytest.raises(DerError):
        read_tlv(bytes.fromhex("308200"))


def test_lenient_truncated_long_form_is_empty():
    tag, length, value, next_pos = read_tlv(
        bytes.fromhex("308200"), strict=False,
    )

    assert (tag, length, value, next_pos) == (0x30, 0, b"", 2)


def test_indefinite_length_rejected():
    with pytest.raises(DerError):
        read_tlv(bytes.fromhex("3080"))


def test_high_tag_number_rejected():
    with pytest.raises(DerError):
        read_tlv(bytes.fromhex("1f0110"))


def test_eof():
    with pytest.raises(DerError):
        read_tlv(b"")
