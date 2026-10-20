"""Тесты NDP-экстрактора."""
import ipaddress
import struct
from dataclasses import dataclass

from paradox.extractors.ndp import NDPExtractor


@dataclass
class MockRecord:
    ts: float
    src_ip: str
    dst_ip: str
    ip_proto: int
    payload: bytes


class MockState:
    pass


def _mac_option(opt_type, mac_str):
    mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
    return struct.pack("!BB", opt_type, 1) + mac_bytes


def test_ndp_extractor():
    state = MockState()
    extractor = NDPExtractor()

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

    extractor.process(r1, state)
    extractor.process(r2, state)

    assert state.ndp_total == 2
    assert state.ndp_neighbors["2001:db8::2"] == "00:11:22:33:44:55"
    assert "fe80::1" in state.ndp_routers
