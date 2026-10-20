"""Тесты агрегатора NDP."""
from dataclasses import dataclass
import ipaddress
import struct

from paradox.analyzers.ndp import analyze_ndp


@dataclass
class MockRecord:
    ts: float
    src_ip: str
    dst_ip: str
    ip_proto: int
    payload: bytes


def _mac_option(opt_type, mac_str):
    mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
    return struct.pack("!BB", opt_type, 1) + mac_bytes


def test_analyze_ndp_empty():
    assert analyze_ndp([]) == {"total": 0, "neighbors": [], "routers": []}


def test_analyze_ndp():
    # NA (neighbor advertisement)
    flags = 0x60
    target_ip = ipaddress.IPv6Address("2001:db8::2").packed
    p1 = struct.pack("!BBH", 136, 0, 0) + struct.pack("!B3x", flags) + target_ip
    p1 += _mac_option(2, "00:11:22:33:44:55")
    r1 = MockRecord(1000.0, "2001:db8::2", "2001:db8::1", 58, p1)

    # RA (router advertisement)
    p2 = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0)
    p2 += _mac_option(1, "aa:bb:cc:dd:ee:ff")
    r2 = MockRecord(1001.0, "fe80::1", "ff02::1", 58, p2)

    # NS (neighbor solicitation)
    target_ip3 = ipaddress.IPv6Address("2001:db8::3").packed
    p3 = struct.pack("!BBH", 135, 0, 0) + b"\x00" * 4 + target_ip3
    p3 += _mac_option(1, "11:22:33:44:55:66")
    r3 = MockRecord(1002.0, "2001:db8::1", "ff02::1:ff00:3", 58, p3)

    res = analyze_ndp([r1, r2, r3])

    assert res["total"] == 3
    assert res["routers"] == ["fe80::1"]

    neighbors = {n["ip"]: n["mac"] for n in res["neighbors"]}
    assert neighbors["2001:db8::2"] == "00:11:22:33:44:55"
    assert neighbors["2001:db8::3"] == "11:22:33:44:55:66"
