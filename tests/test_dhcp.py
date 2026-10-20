"""Тесты DHCP-экстрактора и парсера."""
import struct

from paradox.extractors.dhcp import DHCPExtractor, parse_dhcp
from paradox.models import CaptureState

_MAGIC = b"\x63\x82\x53\x63"


def _build_dhcp(
    op: int = 2,
    xid: int = 0x12345678,
    ciaddr: str = "0.0.0.0",
    yiaddr: str = "192.168.1.50",
    chaddr_mac: str = "aa:bb:cc:dd:ee:ff",
    hostname: str | None = None,
    msg_type: int | None = 5,
) -> bytes:
    """Собрать минимальный DHCP-пакет."""
    def ip_bytes(s):
        return bytes(int(x) for x in s.split("."))

    mac_bytes = bytes(int(x, 16) for x in chaddr_mac.split(":"))
    chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))

    pkt = bytearray()
    pkt.append(op)          # op
    pkt.append(1)           # htype = Ethernet
    pkt.append(6)           # hlen = 6
    pkt.append(0)           # hops
    pkt += struct.pack(">I", xid)   # xid
    pkt += b"\x00\x00"    # secs
    pkt += b"\x00\x00"    # flags
    pkt += ip_bytes(ciaddr)
    pkt += ip_bytes(yiaddr)
    pkt += ip_bytes("0.0.0.0")      # siaddr
    pkt += ip_bytes("0.0.0.0")      # giaddr
    pkt += chaddr                   # 16 bytes
    pkt += b"\x00" * 64            # sname
    pkt += b"\x00" * 128           # file
    pkt += _MAGIC

    # Options
    if msg_type is not None:
        pkt.append(53)
        pkt.append(1)
        pkt.append(msg_type)
    if hostname:
        hn = hostname.encode("ascii")
        pkt.append(12)
        pkt.append(len(hn))
        pkt += hn
    pkt.append(255)  # END

    # Padding до минимальной длины 240+ (уже больше, но на всякий)
    while len(pkt) < 240:
        pkt.append(0)

    return bytes(pkt)


class _Rec:
    """Заглушка PacketRecord для тестов."""
    def __init__(self, payload, src_port=68, dst_port=67):
        self.payload = payload
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = "0.0.0.0"
        self.dst_ip = "255.255.255.255"


# ---------- parse_dhcp ----------

def test_parse_minimal_ack():
    pkt = _build_dhcp(yiaddr="192.168.1.50", msg_type=5)
    info = parse_dhcp(pkt)
    assert info is not None
    assert info["op"] == 2
    assert info["yiaddr"] == "192.168.1.50"
    assert info["chaddr"] == "aa:bb:cc:dd:ee:ff"
    assert info["msg_type"] == 5


def test_parse_with_hostname():
    pkt = _build_dhcp(hostname="laptop-01")
    info = parse_dhcp(pkt)
    assert info["hostname"] == "laptop-01"


def test_parse_too_short():
    assert parse_dhcp(b"\x00" * 100) is None


def test_parse_no_magic():
    pkt = b"\x00" * 240
    assert parse_dhcp(pkt) is None


def test_parse_no_msg_type():
    pkt = _build_dhcp(msg_type=None)
    info = parse_dhcp(pkt)
    assert info["msg_type"] is None


def test_parse_zero_mac():
    pkt = _build_dhcp(chaddr_mac="00:00:00:00:00:00")
    info = parse_dhcp(pkt)
    assert info["chaddr"] == ""


# ---------- DHCPExtractor ----------

def test_extractor_writes_identity():
    pkt = _build_dhcp(
        yiaddr="192.168.1.50",
        chaddr_mac="aa:bb:cc:dd:ee:ff",
        hostname="laptop-01",
    )
    state = CaptureState()
    DHCPExtractor().process(_Rec(pkt), state)

    ident = state.host_identities.get("192.168.1.50")
    assert ident is not None
    assert ident.mac == "aa:bb:cc:dd:ee:ff"
    assert "laptop-01" in ident.hostnames


def test_extractor_ignores_non_dhcp_port():
    pkt = _build_dhcp()
    state = CaptureState()
    DHCPExtractor().process(_Rec(pkt, src_port=53, dst_port=53), state)
    assert not state.host_identities


def test_extractor_ignores_empty_payload():
    state = CaptureState()
    DHCPExtractor().process(_Rec(b""), state)
    assert not state.host_identities


def test_extractor_uses_ciaddr_when_yiaddr_zero():
    pkt = _build_dhcp(
        ciaddr="10.0.0.5",
        yiaddr="0.0.0.0",
        chaddr_mac="11:22:33:44:55:66",
    )
    state = CaptureState()
    DHCPExtractor().process(_Rec(pkt), state)
    ident = state.host_identities.get("10.0.0.5")
    assert ident is not None
    assert ident.mac == "11:22:33:44:55:66"


def test_extractor_ignores_both_zero():
    pkt = _build_dhcp(ciaddr="0.0.0.0", yiaddr="0.0.0.0")
    state = CaptureState()
    DHCPExtractor().process(_Rec(pkt), state)
    assert not state.host_identities


def test_extractor_merges_with_existing_identity():
    """Если IP уже в host_identities (например, из ARP) — дополняем."""
    from paradox.models import HostIdentity
    state = CaptureState()
    state.host_identities["192.168.1.50"] = HostIdentity(
        ip="192.168.1.50", mac="11:11:11:11:11:11",
    )
    pkt = _build_dhcp(
        yiaddr="192.168.1.50",
        chaddr_mac="aa:bb:cc:dd:ee:ff",
        hostname="new-host",
    )
    DHCPExtractor().process(_Rec(pkt), state)

    ident = state.host_identities["192.168.1.50"]
    # DHCP перетирает MAC (более авторитетный источник)
    assert ident.mac == "aa:bb:cc:dd:ee:ff"
    assert "new-host" in ident.hostnames
