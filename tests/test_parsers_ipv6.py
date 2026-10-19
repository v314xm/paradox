"""Тесты IPv6-парсера."""
import ipaddress
import struct

import pytest

from pcap_triage.parsers_ipv6 import parse_ipv6_packet


def _ipv6_header(src, dst, next_header=6, payload_len=20, hop_limit=64,
                 flow_label=0, tclass=0):
    ver_tc_fl = (6 << 28) | (tclass << 20) | flow_label
    src_b = ipaddress.IPv6Address(src).packed
    dst_b = ipaddress.IPv6Address(dst).packed
    return struct.pack(
        "!IHBB16s16s", ver_tc_fl, payload_len, next_header, hop_limit,
        src_b, dst_b,
    )


def _tcp_header(src_port=12345, dst_port=443, payload=b""):
    return struct.pack("!HHIIBBHHH", src_port, dst_port,
                       0, 0, 5 << 4, 0x10, 0, 0, 0) + payload


def _udp_header(src_port=53, dst_port=53, payload=b""):
    return struct.pack("!HHHH", src_port, dst_port,
                       len(payload) + 8, 0) + payload


def test_ipv6_tcp():
    tcp = _tcp_header(src_port=12345, dst_port=443)
    ipv6 = _ipv6_header("2001:db8::1", "2001:db8::2", next_header=6,
                        payload_len=len(tcp))
    rec = parse_ipv6_packet(ipv6 + tcp, ts=1000.0)
    assert rec.src_ip == "2001:db8::1"
    assert rec.dst_ip == "2001:db8::2"
    assert rec.ip_proto == 6
    assert rec.src_port == 12345
    assert rec.dst_port == 443
    assert rec.ipv6_meta["version"] == 6
    assert rec.ipv6_meta["extension_chain"] == ()
    assert rec.ipv6_meta["is_fragment"] is False


def test_ipv6_udp():
    udp = _udp_header(src_port=5353, dst_port=53, payload=b"\x00")
    ipv6 = _ipv6_header("fe80::1", "ff02::fb", next_header=17,
                        payload_len=len(udp))
    rec = parse_ipv6_packet(ipv6 + udp, ts=1001.0)
    assert rec.src_port == 5353
    assert rec.dst_port == 53
    assert rec.ip_proto == 17


def test_ipv6_link_local():
    tcp = _tcp_header()
    ipv6 = _ipv6_header("fe80::aabb:ccdd:eeff:0011", "fe80::1",
                        next_header=6, payload_len=len(tcp))
    rec = parse_ipv6_packet(ipv6 + tcp, ts=1002.0)
    assert rec.src_ip.startswith("fe80::")
    assert ipaddress.IPv6Address(rec.src_ip).is_link_local


def test_ipv6_hop_by_hop():
    hbh = bytes([6, 0]) + b"\x00" * 6
    tcp = _tcp_header(src_port=5000, dst_port=80)
    ipv6 = _ipv6_header("2001:db8::1", "2001:db8::2", next_header=0,
                        payload_len=len(hbh) + len(tcp))
    rec = parse_ipv6_packet(ipv6 + hbh + tcp, ts=1003.0)
    assert rec.ip_proto == 6
    assert rec.src_port == 5000
    assert rec.dst_port == 80
    assert 0 in rec.ipv6_meta["extension_chain"]


def test_ipv6_fragment():
    frag = struct.pack("!BBHI", 17, 0, 0x0001, 0xDEADBEEF)
    udp = _udp_header(src_port=1234, dst_port=5678, payload=b"abc")
    ipv6 = _ipv6_header("2001:db8::1", "2001:db8::2", next_header=44,
                        payload_len=len(frag) + len(udp))
    rec = parse_ipv6_packet(ipv6 + frag + udp, ts=1004.0)
    assert rec.ipv6_meta["is_fragment"] is True
    assert rec.ipv6_meta["fragment_id"] == 0xDEADBEEF
    assert rec.ipv6_meta["fragment_offset"] == 0
    assert 44 in rec.ipv6_meta["extension_chain"]


def test_ipv6_fragment_offset():
    flags = (100 << 3) | 1
    frag = struct.pack("!BBHI", 17, 0, flags, 0x12345678)
    ipv6 = _ipv6_header("2001:db8::1", "2001:db8::2", next_header=44,
                        payload_len=len(frag))
    rec = parse_ipv6_packet(ipv6 + frag, ts=1005.0)
    assert rec.ipv6_meta["fragment_offset"] == 800


def test_ipv6_double_extension():
    hbh = bytes([60, 0]) + b"\x00" * 6
    dopt = bytes([6, 0]) + b"\x00" * 6
    tcp = _tcp_header()
    ipv6 = _ipv6_header("2001:db8::1", "2001:db8::2", next_header=0,
                        payload_len=len(hbh) + len(dopt) + len(tcp))
    rec = parse_ipv6_packet(ipv6 + hbh + dopt + tcp, ts=1006.0)
    assert rec.ip_proto == 6
    assert 0 in rec.ipv6_meta["extension_chain"]
    assert 60 in rec.ipv6_meta["extension_chain"]


def test_ipv6_extension_chain_too_long():
    chain = b""
    for _ in range(20):
        chain += bytes([0, 0]) + b"\x00" * 6
    ipv6 = _ipv6_header("2001:db8::1", "2001:db8::2", next_header=0,
                        payload_len=len(chain))
    rec = parse_ipv6_packet(ipv6 + chain, ts=1007.0)
    assert len(rec.ipv6_meta["extension_chain"]) <= 16


def test_ipv6_truncated_header():
    rec = parse_ipv6_packet(b"\x60" * 10, ts=1008.0)
    assert rec.src_ip == ""
    assert rec.dst_ip == ""


def test_ipv6_not_v6():
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0, 0, 64, 6, 0,
                       b"\x01\x01\x01\x01", b"\x02\x02\x02\x02")
    rec = parse_ipv6_packet(ipv4 + b"\x00" * 20, ts=1009.0)
    assert rec.src_ip == ""


def test_ipv6_esp_payload():
    esp = b"\x00" * 16
    ipv6 = _ipv6_header("2001:db8::1", "2001:db8::2", next_header=50,
                        payload_len=len(esp))
    rec = parse_ipv6_packet(ipv6 + esp, ts=1010.0)
    assert rec.ip_proto == 50
    assert rec.src_port is None
    assert rec.dst_port is None
