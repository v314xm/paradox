"""Регрессии P1: padding в payload, разрывы/память reassembler'а,
IPv6 TCP-поля, windowed ratio nxdomain_burst.
"""
from __future__ import annotations

import ipaddress
import socket
import struct

from paradox.config import Config
from paradox.detectors.nxdomain_burst import NXDOMAINBurstDetector
from paradox.models import CaptureState, FlowKey
from paradox.parsers import PacketRecord, parse_packet
from paradox.reassembler import TCPReassembler


def _eth(ethertype: int, l3: bytes) -> bytes:
    return (
        b"\x00\x11\x22\x33\x44\x66"
        b"\x00\x11\x22\x33\x44\x55"
        + struct.pack("!H", ethertype)
        + l3
    )


def _ipv4_tcp(payload: bytes) -> bytes:
    """IPv4 + TCP + payload, total length корректен (без padding)."""
    tcp = struct.pack(
        "!HHIIBBHHH",
        40000, 80, 1, 0,  # sport, dport, seq, ack
        0x50, 0x18, 8192, 0, 0,  # data_offset, flags, window, csum, urg
    ) + payload
    ihl = 20
    total_len = ihl + len(tcp)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 1, 0,
        64, 6, 0,
        socket.inet_aton("192.168.1.10"),
        socket.inet_aton("8.8.8.8"),
    )
    return ipv4 + tcp


def test_ipv4_payload_excludes_ethernet_padding():
    frame = _eth(0x0800, _ipv4_tcp(b"HELLO"))
    # Дополняем кадр до минимальных 60 байт.
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))

    rec = parse_packet(frame, 1.0)

    assert rec.proto == "tcp"
    assert rec.payload == b"HELLO"


def test_ipv6_tcp_has_seq_and_payload():
    src = ipaddress.IPv6Address("2001:db8::1").packed
    dst = ipaddress.IPv6Address("2001:db8::2").packed
    tcp = struct.pack(
        "!HHIIBBHHH",
        40000, 443, 0x12345678, 0x9ABCDEF0,
        0x50, 0x18, 8192, 0, 0,
    ) + b"ABCD"
    payload_len = len(tcp)
    ipv6 = struct.pack("!IHBB16s16s", 6 << 28, payload_len, 6, 64, src, dst)

    rec = parse_packet(_eth(0x86DD, ipv6 + tcp), 1.0)

    assert rec.proto == "tcp"
    assert rec.src_ip == "2001:db8::1"
    assert rec.tcp_seq == 0x12345678
    assert rec.tcp_ack == 0x9ABCDEF0
    assert rec.payload == b"ABCD"


def _tcp_record(seq: int, payload: bytes, flags: int, sport: int = 1234) -> PacketRecord:
    return PacketRecord(
        ts=0.0, length=0, raw=b"",
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        proto="tcp", src_port=sport, dst_port=80,
        tcp_seq=seq, tcp_flags=flags, payload=payload,
    )


def test_reassembler_flags_gap_as_truncated():
    r = TCPReassembler()
    r.feed(_tcp_record(0, b"", flags=0x02))          # SYN, base=0
    r.feed(_tcp_record(1, b"AAAA", flags=0x18))      # offset 1..4
    r.feed(_tcp_record(9, b"CCCC", flags=0x18))      # offset 9..12 — дыра 5..8
    r.feed(_tcp_record(13, b"", flags=0x01))         # FIN

    key = FlowKey("tcp", "10.0.0.1", "10.0.0.2", 1234, 80)
    assert key in r.truncated_flows()


def test_reassembler_total_memory_cap_covers_finalized():
    r = TCPReassembler(max_bytes_per_flow=1_000_000, max_total_bytes=300)

    # flow1: 200 байт, flow2: 200 байт. Второй не должен влезть.
    r.feed(_tcp_record(0, b"", flags=0x02, sport=1234))
    r.feed(_tcp_record(1, b"A" * 200, flags=0x18, sport=1234))
    r.feed(_tcp_record(0, b"", flags=0x02, sport=1235))
    r.feed(_tcp_record(1, b"B" * 200, flags=0x18, sport=1235))
    r.finalize_all()

    key2 = FlowKey("tcp", "10.0.0.1", "10.0.0.2", 1235, 80)
    assert key2 in r.truncated_flows()
    assert len(r.all_streams()) == 1


def test_nxdomain_burst_uses_windowed_ratio():
    state = CaptureState()
    state.dns_nxdomain_by_src["10.0.0.1"] = 6
    # 6 NXDOMAIN в одном 60-секундном окне.
    state.dns_nxdomain_ts_by_src["10.0.0.1"] = [100 + i for i in range(6)]
    # 6 запросов в том же окне + 994 запроса позже, разнесённых на
    # тысячи секунд (в окно 60 с больше 6 не попадёт).
    state.dns_query_ts_by_src["10.0.0.1"] = (
        [100 + i for i in range(6)] + [100000 + i * 1000 for i in range(994)]
    )
    state.dns_queries_by_src["10.0.0.1"] = {"mixed.example": 1000}

    findings = NXDOMAINBurstDetector().run(state, Config())

    # Старый total-ratio (6/1000=0.006) отсеял бы; windowed 6/6=1.0 — нет.
    assert len(findings) == 1
    assert findings[0].evidence["dns_in_window"] == 6
