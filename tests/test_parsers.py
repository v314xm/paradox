"""
Unit-тесты быстрого парсера.

Проверяем разбор сырых байтов в PacketRecord. Без scapy, без pcap.
Эталонные пакеты собраны вручную из hex-дампов.
"""
from paradox.parsers import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    IP_PROTO_ICMP,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    parse_packet,
)

# ---------- эталонные блоки ----------

ETHERNET_HEADER = bytes.fromhex(
    "aabbccddee01"    # dst MAC
    "aabbccddee02"    # src MAC
    "0800"            # ethertype IPv4
)

ETHERNET_HEADER_ARP = bytes.fromhex(
    "ffffffffffff"    # dst MAC broadcast
    "aabbccddee02"    # src MAC
    "0806"            # ethertype ARP
)

IPV4_HEADER_TCP = bytes.fromhex(
    "45"              # version=4, IHL=5
    "00"              # DSCP
    "0028"            # total_length=40
    "0000"            # ip_id
    "4000"            # flags=DF, frag_offset=0
    "40"              # TTL=64
    "06"              # protocol=TCP
    "0000"            # checksum
    "c0a80164"        # 192.168.1.100
    "cb007142"        # 203.0.113.66
)

TCP_SYN = bytes.fromhex(
    "cf08"            # src_port 53000
    "115c"            # dst_port 4444
    "00000000"        # seq
    "00000000"        # ack
    "50"              # data_offset=5
    "02"              # flags=SYN
    "ffff"            # window
    "0000"            # checksum
    "0000"            # urgent
)

TCP_DATA = bytes.fromhex(
    "cf08"            # src_port 53000
    "0050"            # dst_port 80
    "00000000"        # seq
    "00000000"        # ack
    "50"              # data_offset=5
    "18"              # flags=PSH+ACK
    "ffff"            # window
    "0000"            # checksum
    "0000"            # urgent
) + b"GET /"


# ---------- TCP ----------

def test_parse_tcp_syn():
    raw = ETHERNET_HEADER + IPV4_HEADER_TCP + TCP_SYN
    rec = parse_packet(raw, ts=1.5)

    assert rec.ts == 1.5
    assert rec.length == 54
    assert rec.proto == "tcp"

    assert rec.eth_src == "aa:bb:cc:dd:ee:02"
    assert rec.eth_dst == "aa:bb:cc:dd:ee:01"
    assert rec.ethertype == ETHERTYPE_IPV4

    assert rec.src_ip == "192.168.1.100"
    assert rec.dst_ip == "203.0.113.66"
    assert rec.ip_proto == IP_PROTO_TCP

    assert rec.src_port == 53000
    assert rec.dst_port == 4444
    assert rec.tcp_seq == 0
    assert rec.tcp_ack == 0
    assert rec.tcp_flags == 0x02

    assert rec.payload == b""


def test_parse_tcp_with_payload():
    raw = ETHERNET_HEADER + IPV4_HEADER_TCP + TCP_DATA
    rec = parse_packet(raw, ts=2.0)

    assert rec.proto == "tcp"
    assert rec.dst_port == 80
    assert rec.tcp_flags == 0x18
    assert rec.payload == b"GET /"


# ---------- UDP ----------

def test_parse_udp():
    ipv4 = bytes.fromhex(
        "45 00 001c 0000 0000 40 11 0000 c0a80164 01010101"
    )
    udp = bytes.fromhex("3039 007b 0008 0000")
    raw = ETHERNET_HEADER + ipv4 + udp + b"hello"

    rec = parse_packet(raw, ts=3.0)

    assert rec.proto == "udp"
    assert rec.src_ip == "192.168.1.100"
    assert rec.dst_ip == "1.1.1.1"
    assert rec.ip_proto == IP_PROTO_UDP
    assert rec.src_port == 12345
    assert rec.dst_port == 123
    assert rec.payload == b"hello"


# ---------- ICMP ----------

def test_parse_icmp():
    ipv4 = bytes.fromhex(
        "45 00 0020 0000 0000 40 01 0000 c0a80164 08080808"
    )
    icmp = bytes.fromhex("0800 0000 0000 0001")
    raw = ETHERNET_HEADER + ipv4 + icmp

    rec = parse_packet(raw, ts=4.0)

    assert rec.proto == "icmp"
    assert rec.src_ip == "192.168.1.100"
    assert rec.dst_ip == "8.8.8.8"
    assert rec.ip_proto == IP_PROTO_ICMP
    assert rec.payload == icmp


# ---------- ARP ----------

def test_parse_arp_request():
    arp = bytes.fromhex(
        "0001"            # htype Ethernet
        "0800"            # ptype IPv4
        "06"              # hlen
        "04"              # plen
        "0001"            # op=request
        "aabbccddee02"    # sender MAC
        "c0a80164"        # sender IP 192.168.1.100
        "000000000000"    # target MAC
        "00000000"        # target IP 0.0.0.0
    )
    raw = ETHERNET_HEADER_ARP + arp

    rec = parse_packet(raw, ts=5.0)

    assert rec.proto == "arp"
    assert rec.ethertype == ETHERTYPE_ARP
    assert rec.eth_dst == "ff:ff:ff:ff:ff:ff"
    assert rec.eth_src == "aa:bb:cc:dd:ee:02"
    assert rec.arp_op == 1
    assert rec.arp_sender_mac == "aa:bb:cc:dd:ee:02"
    assert rec.arp_sender_ip == "192.168.1.100"
    assert rec.arp_target_mac == "00:00:00:00:00:00"
    assert rec.arp_target_ip == "0.0.0.0"


# ---------- VLAN ----------

def test_parse_vlan():
    vlan = bytes.fromhex("0064 0800")  # VLAN id=100, inner IPv4
    raw = bytes.fromhex(
        "aabbccddee01aabbccddee02" "8100"
    ) + vlan + IPV4_HEADER_TCP + TCP_SYN

    rec = parse_packet(raw, ts=6.0)

    assert rec.vlan_id == 100
    assert rec.ethertype == ETHERTYPE_IPV4
    assert rec.proto == "tcp"
    assert rec.src_port == 53000


# ---------- IPv4 фрагментация ----------

def test_parse_ipv4_first_fragment():
    """Первый фрагмент (MF=1, offset=0) — L4-заголовок виден."""
    ipv4 = bytes.fromhex(
        "45 00 0028 1234 2000 40 06 0000 c0a80164 cb007142"
    )
    raw = ETHERNET_HEADER + ipv4 + TCP_SYN

    rec = parse_packet(raw, ts=7.0)

    assert rec.ip_id == 0x1234
    assert rec.ip_mf is True
    assert rec.ip_frag_offset == 0
    assert rec.proto == "tcp"
    assert rec.src_port == 53000


def test_parse_ipv4_later_fragment():
    """Не-первый фрагмент — L4-заголовок не виден."""
    ipv4 = bytes.fromhex(
        "45 00 0014 1234 2001 40 06 0000 c0a80164 cb007142"
    )
    raw = ETHERNET_HEADER + ipv4 + b"\xde\xad\xbe\xef"

    rec = parse_packet(raw, ts=8.0)

    assert rec.ip_id == 0x1234
    assert rec.ip_mf is True
    assert rec.ip_frag_offset == 8
    assert rec.proto == "ipv4_fragment"
    assert rec.payload == b"\xde\xad\xbe\xef"


# ---------- edge cases ----------

def test_parse_short_ethernet():
    raw = b"\x00" * 5
    rec = parse_packet(raw, ts=9.0)

    assert rec.proto == "other"
    assert rec.src_ip is None
    assert rec.dst_ip is None
    assert rec.length == 5


def test_parse_unknown_ethertype():
    """LLDP (0x88CC) — не наш протокол."""
    raw = bytes.fromhex("aabbccddee01aabbccddee02" "88cc") + b"\x00" * 20
    rec = parse_packet(raw, ts=10.0)

    assert rec.proto == "other"
    assert rec.ethertype == 0x88CC
    assert rec.src_ip is None


def test_parse_ipv6_stub():
    """IPv6 пока не поддержан — только ethertype."""
    raw = bytes.fromhex("aabbccddee01aabbccddee02" "86dd") + b"\x00" * 40
    rec = parse_packet(raw, ts=11.0)

    assert rec.proto == "other"
    assert rec.ethertype == 0x86DD