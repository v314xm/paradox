"""
Быстрый парсер сырых пакетов.

Единственное место, где работаем с байтами напрямую через struct.
Scapy остаётся в проекте, но используется точечно — для payload
сложной структуры (DNS, TLS ClientHello, HTTP). Здесь только
базовый L2-L4 разбор, дешёвый и быстрый.

Принципы:
- все L2-L4 заголовки разбираются сразу (десятки struct.unpack,
  наносекунды на пакет);
- payload не парсится — это работа экстракторов по требованию;
- raw сохраняется целиком — escape hatch для L1-L4 уровней;
- IPv6 пока заглушка (proto="other").

Поддерживается:
- Ethernet (linktype=1)
- 802.1Q VLAN (один тег)
- IPv4 (+ фрагментация: ip_id, ip_frag_offset, ip_mf)
- TCP (с seq/ack/flags)
- UDP
- ICMP
- ARP (Ethernet + IPv4)

Не поддерживается (пока):
- IPv6 (только заглушка)
- Не-Ethernet linktype (Linux SLL, RAW IP)
- TCP reassembly — payload это один TCP-сегмент
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# --- размеры заголовков ---
ETHERNET_HEADER_LEN = 14
VLAN_TAG_LEN = 4
IPV4_MIN_HEADER_LEN = 20
TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8

# Заголовки читаются одним unpack_from: на 627k пакетов это заметно
# дешевле, чем по одному struct.unpack_from на поле.
_ETH = struct.Struct("!6s6sH")
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIBBHHH")
ARP_BASE_HEADER_LEN = 8  # без адресов

# --- ethertype ---
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

# --- IP protocols ---
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


@dataclass(slots=True)
class PacketRecord:
    """Нормализованный пакет для экстракторов.

    Все поля — простые типы. Никаких ссылок на scapy-объекты.
    Поля с None не применимы для данного пакета (например, tcp_seq
    для UDP-пакета).
    """
    # мета
    ts: float
    length: int
    raw: bytes

    # L2
    eth_src: str | None = None
    eth_dst: str | None = None
    ethertype: int | None = None
    vlan_id: int | None = None

    # L3
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_proto: int | None = None
    ip_id: int | None = None
    ip_frag_offset: int = 0
    ip_mf: bool = False

    # L4 общее
    proto: str = "other"  # "tcp" | "udp" | "icmp" | "arp" | "ipv4_fragment" | "other"
    src_port: int | None = None
    dst_port: int | None = None

    # TCP-specific
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_flags: int | None = None

    # ARP-specific (заполняется только для ARP-пакетов)
    arp_op: int | None = None
    arp_sender_mac: str | None = None
    arp_sender_ip: str | None = None
    arp_target_mac: str | None = None
    arp_target_ip: str | None = None

    # L4-payload (или сырые байты для не-первых IPv4-фрагментов)
    payload: bytes = b""

    # Метаданные IPv6 (extension chain, fragment info)
    ipv6_meta: dict | None = None


def parse_packet(raw: bytes, ts: float) -> PacketRecord:
    """Разобрать сырые байты пакета в PacketRecord."""
    length = len(raw)
    rec = PacketRecord(ts=ts, length=length, raw=raw)

    if length < ETHERNET_HEADER_LEN:
        return rec

    rec.eth_dst, rec.eth_src, ethertype = _ETH.unpack_from(raw, 0)
    rec.eth_dst = rec.eth_dst.hex(":")
    rec.eth_src = rec.eth_src.hex(":")
    offset = ETHERNET_HEADER_LEN

    # 802.1Q VLAN
    if ethertype == ETHERTYPE_VLAN:
        if length < offset + VLAN_TAG_LEN:
            rec.ethertype = ethertype
            return rec
        tci = struct.unpack_from("!H", raw, offset)[0]
        rec.vlan_id = tci & 0x0FFF
        ethertype = struct.unpack_from("!H", raw, offset + 2)[0]
        offset += VLAN_TAG_LEN

    rec.ethertype = ethertype

    if ethertype == ETHERTYPE_IPV4:
        _parse_ipv4(raw, rec, offset)
    elif ethertype == ETHERTYPE_ARP:
        _parse_arp(raw, rec, offset)
    elif ethertype == ETHERTYPE_IPV6:
        from paradox.parsers_ipv6 import parse_ipv6_packet
        ipv6_rec = parse_ipv6_packet(
            raw[offset:], ts,
            eth_src=rec.eth_src, eth_dst=rec.eth_dst,
            ethertype=ethertype, vlan_id=rec.vlan_id,
            length=length, raw=raw,
        )
        rec.src_ip = ipv6_rec.src_ip
        rec.dst_ip = ipv6_rec.dst_ip
        rec.ip_proto = ipv6_rec.ip_proto
        rec.src_port = ipv6_rec.src_port
        rec.dst_port = ipv6_rec.dst_port
        rec.payload = ipv6_rec.payload
        rec.tcp_seq = ipv6_rec.tcp_seq
        rec.tcp_ack = ipv6_rec.tcp_ack
        rec.tcp_flags = ipv6_rec.tcp_flags
        if ipv6_rec.ip_proto == 6:
            rec.proto = "tcp"
        elif ipv6_rec.ip_proto == 17:
            rec.proto = "udp"
        elif ipv6_rec.ip_proto == 58:
            rec.proto = "icmpv6"
        else:
            rec.proto = "other"
        rec.ipv6_meta = getattr(ipv6_rec, "ipv6_meta", None)
    else:
        rec.proto = "other"

    return rec


def _parse_ipv4(raw: bytes, rec: PacketRecord, offset: int) -> None:
    length = len(raw)
    if length < offset + IPV4_MIN_HEADER_LEN:
        return

    (
        ver_ihl, _tos, total_len, ip_id, flags_frag,
        _ttl, ip_proto, _checksum, src, dst,
    ) = _IPV4.unpack_from(raw, offset)

    ihl = (ver_ihl & 0x0F) * 4
    if ihl < IPV4_MIN_HEADER_LEN or length < offset + ihl:
        return

    rec.ip_proto = ip_proto
    rec.ip_id = ip_id

    rec.ip_mf = bool((flags_frag >> 13) & 1)
    rec.ip_frag_offset = (flags_frag & 0x1FFF) * 8

    rec.src_ip = socket.inet_ntoa(src)
    rec.dst_ip = socket.inet_ntoa(dst)

    # total length определяет реальный конец IP-пакета. Без него
    # Ethernet-padding (кадры меньше 60 байт) попадает в payload и
    # в reassembler'е занимает offset реального сегмента.
    if total_len >= IPV4_MIN_HEADER_LEN and offset + total_len <= length:
        ip_end = offset + total_len
    else:
        # TSO/jumbo-кадры: total length бывает 0 или больше caplen —
        # берём весь кадр, чтобы не резать настоящие данные.
        ip_end = length

    l4_offset = offset + ihl

    # Не-первый фрагмент: L4-заголовок был в первом фрагменте
    if rec.ip_frag_offset > 0:
        rec.proto = "ipv4_fragment"
        rec.payload = raw[l4_offset:ip_end]
        return

    if rec.ip_proto == IP_PROTO_TCP:
        _parse_tcp(raw, rec, l4_offset, ip_end)
    elif rec.ip_proto == IP_PROTO_UDP:
        _parse_udp(raw, rec, l4_offset, ip_end)
    elif rec.ip_proto == IP_PROTO_ICMP:
        _parse_icmp(raw, rec, l4_offset)
    else:
        rec.proto = "other"
        rec.payload = raw[l4_offset:ip_end]


def _parse_tcp(raw: bytes, rec: PacketRecord, offset: int, end: int) -> None:
    if end < offset + TCP_MIN_HEADER_LEN:
        rec.proto = "tcp"
        return

    (
        src_port, dst_port, tcp_seq, tcp_ack,
        data_off_flags, tcp_flags, _win, _checksum, _urg,
    ) = _TCP.unpack_from(raw, offset)

    rec.src_port = src_port
    rec.dst_port = dst_port
    rec.tcp_seq = tcp_seq
    rec.tcp_ack = tcp_ack

    data_offset = (data_off_flags >> 4) * 4
    data_offset = max(data_offset, TCP_MIN_HEADER_LEN)
    rec.tcp_flags = tcp_flags

    payload_start = offset + data_offset
    rec.payload = raw[payload_start:end] if payload_start < end else b""
    rec.proto = "tcp"


def _parse_udp(raw: bytes, rec: PacketRecord, offset: int, end: int) -> None:
    if end < offset + UDP_HEADER_LEN:
        rec.proto = "udp"
        return

    rec.src_port = struct.unpack_from("!H", raw, offset)[0]
    rec.dst_port = struct.unpack_from("!H", raw, offset + 2)[0]

    payload_start = offset + UDP_HEADER_LEN
    rec.payload = raw[payload_start:end] if payload_start < end else b""
    rec.proto = "udp"


def _parse_icmp(raw: bytes, rec: PacketRecord, offset: int) -> None:
    rec.proto = "icmp"
    rec.payload = raw[offset:]


def _parse_arp(raw: bytes, rec: PacketRecord, offset: int) -> None:
    length = len(raw)
    if length < offset + ARP_BASE_HEADER_LEN:
        rec.proto = "arp"
        return

    htype = struct.unpack_from("!H", raw, offset)[0]
    ptype = struct.unpack_from("!H", raw, offset + 2)[0]
    hlen = raw[offset + 4]
    plen = raw[offset + 5]
    rec.arp_op = struct.unpack_from("!H", raw, offset + 6)[0]

    # Поддерживаем только Ethernet (htype=1, hlen=6) + IPv4 (ptype=0x0800, plen=4)
    if htype != 1 or ptype != ETHERTYPE_IPV4 or hlen != 6 or plen != 4:
        rec.proto = "arp"
        rec.payload = raw[offset + ARP_BASE_HEADER_LEN:]
        return

    addr_offset = offset + ARP_BASE_HEADER_LEN
    if length < addr_offset + 2 * hlen + 2 * plen:
        rec.proto = "arp"
        return

    rec.arp_sender_mac = raw[addr_offset:addr_offset + hlen].hex(":")
    rec.arp_sender_ip = socket.inet_ntoa(
        raw[addr_offset + hlen:addr_offset + hlen + plen]
    )
    rec.arp_target_mac = raw[
        addr_offset + hlen + plen:addr_offset + 2 * hlen + plen
    ].hex(":")
    rec.arp_target_ip = socket.inet_ntoa(
        raw[addr_offset + 2 * hlen + plen:addr_offset + 2 * hlen + 2 * plen]
    )
    rec.proto = "arp"
