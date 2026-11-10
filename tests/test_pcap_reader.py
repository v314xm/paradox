"""Тесты минимального читателя pcap: порядок байт, наносекунды, обрыв."""
import hashlib
import io
import struct

import pytest

from paradox.pcap_reader import PcapFormatError, PcapRecordReader

LE = b"\xd4\xc3\xb2\xa1"
BE = b"\xa1\xb2\xc3\xd4"
LE_NANO = b"\x4d\x3c\xb2\xa1"
BE_NANO = b"\xa1\xb2\x3c\x4d"


def _pcap(records, *, magic=LE, endian="<", trailing=b"") -> bytes:
    header = magic + struct.pack(
        endian + "HHIIII", 2, 4, 0, 0, 65535, 1,
    )
    body = b""
    for sec, frac, data in records:
        body += struct.pack(
            endian + "IIII", sec, frac, len(data), len(data),
        ) + data
    return header + body + trailing


def test_little_endian_microseconds():
    raw = _pcap([(10, 500_000, b"abc")])
    reader = PcapRecordReader(io.BytesIO(raw))

    packets = list(reader)

    assert packets == [(b"abc", 10.5)]
    assert reader.complete is True
    assert reader.bytes_hashed == len(raw)
    assert reader.hexdigest() == hashlib.sha256(raw).hexdigest()


def test_big_endian_nanoseconds():
    raw = _pcap(
        [(1, 250_000_000, b"xy")], magic=BE_NANO, endian=">",
    )
    reader = PcapRecordReader(io.BytesIO(raw))

    packets = list(reader)

    assert packets == [(b"xy", 1.25)]


def test_big_endian_microseconds():
    raw = _pcap([(2, 1, b"z")], magic=BE, endian=">")
    reader = PcapRecordReader(io.BytesIO(raw))

    assert list(reader) == [(b"z", 2.000001)]


def test_trailing_garbage_stops_without_full_hash():
    raw = _pcap([(1, 0, b"a")], trailing=b"\x00\x01\x02")
    reader = PcapRecordReader(io.BytesIO(raw))

    assert list(reader) == [(b"a", 1.0)]
    assert reader.complete is False
    assert reader.bytes_hashed < len(raw)
    assert reader.hexdigest() != hashlib.sha256(raw).hexdigest()


def test_empty_pcap_is_complete():
    raw = _pcap([])
    reader = PcapRecordReader(io.BytesIO(raw))

    assert list(reader) == []
    assert reader.complete is True


def test_pcapng_magic_rejected():
    raw = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20

    with pytest.raises(PcapFormatError, match="сигнатура"):
        PcapRecordReader(io.BytesIO(raw))


def test_short_global_header_rejected():
    with pytest.raises(PcapFormatError, match="оборван"):
        PcapRecordReader(io.BytesIO(LE + b"\x00" * 4))


def test_truncated_record_data_rejected():
    raw = _pcap([(1, 0, b"abcdef")])
    with pytest.raises(PcapFormatError, match="оборван"):
        list(PcapRecordReader(io.BytesIO(raw[:-3])))
