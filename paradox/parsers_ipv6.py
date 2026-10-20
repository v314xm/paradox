"""IPv6-парсер пакетов.

Отдельный модуль. Возвращает PacketRecord, совместимый с IPv4-парсером.
Экстракторы работают с record.src_ip / dst_ip / src_port / dst_port —
им всё равно, IPv4 это или IPv6 (IP хранятся строками).

Метаданные кладутся в record.ipv6_meta (dict):
    {
      "version": 6,
      "traffic_class": int,
      "flow_label": int,
      "hop_limit": int,
      "payload_length": int,
      "extension_chain": tuple[int, ...],
      "is_fragment": bool,
      "fragment_offset": int,
      "fragment_id": int | None,
      "final_next_header": int,
    }
"""
from __future__ import annotations

import ipaddress
import struct
from typing import Any

EXT_HOP_BY_HOP = 0
EXT_ROUTING = 43
EXT_FRAGMENT = 44
EXT_ESP = 50
EXT_AUTH = 51
EXT_DEST_OPTIONS = 60
EXT_MOBILITY = 135

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

_EXTENSIONS = {
    EXT_HOP_BY_HOP,
    EXT_ROUTING,
    EXT_FRAGMENT,
    EXT_DEST_OPTIONS,
    EXT_AUTH,
    EXT_MOBILITY,
}

_MAX_EXTENSIONS = 16


def parse_ipv6_packet(
    payload: bytes,
    ts: float,
    eth_src: str | None = None,
    eth_dst: str | None = None,
    ethertype: int = 0x86DD,
    vlan_id: int | None = None,
    length: int | None = None,
    raw: bytes | None = None,
):
    """Разобрать IPv6-пакет. Возвращает PacketRecord.

    payload — байты начиная с IPv6-заголовка (после Ethernet/VLAN).
    length/raw — полные длина и сырые байты кадра (для совместимости
    с PacketRecord). Если не переданы — используются len(payload)/payload.
    """
    from paradox.parsers import PacketRecord

    total_length = length if length is not None else len(payload)
    total_raw = raw if raw is not None else payload

    if len(payload) < 40:
        return _make_record(
            PacketRecord, ts, eth_src, eth_dst, ethertype, vlan_id,
            src_ip="", dst_ip="", payload=b"",
            length=total_length, raw=total_raw,
        )

    ver_tc_fl, payload_len, next_header, hop_limit, src, dst = struct.unpack(
        "!IHBB16s16s", payload[:40],
    )

    version = (ver_tc_fl >> 28) & 0x0F
    if version != 6:
        return _make_record(
            PacketRecord, ts, eth_src, eth_dst, ethertype, vlan_id,
            src_ip="", dst_ip="", payload=b"",
            length=total_length, raw=total_raw,
        )

    tclass = (ver_tc_fl >> 20) & 0xFF
    flow_label = ver_tc_fl & 0xFFFFF

    src_ip = str(ipaddress.IPv6Address(src))
    dst_ip = str(ipaddress.IPv6Address(dst))

    rest = payload[40:40 + payload_len] if payload_len else payload[40:]

    extension_chain: list[int] = []
    is_fragment = False
    fragment_offset = 0
    fragment_id: int | None = None

    nh = next_header
    offset = 0
    iterations = 0

    while nh in _EXTENSIONS and offset + 2 <= len(rest):
        iterations += 1
        if iterations > _MAX_EXTENSIONS:
            break
        extension_chain.append(nh)

        if nh == EXT_FRAGMENT:
            if offset + 8 > len(rest):
                break
            fr_next, _res, fr_off_flags, fr_id = struct.unpack(
                "!BBHI", rest[offset:offset + 8],
            )
            fragment_offset = (fr_off_flags >> 3) * 8
            is_fragment = True
            fragment_id = fr_id
            nh = fr_next
            offset += 8
            continue

        if nh in (EXT_AUTH, EXT_ESP):
            if nh == EXT_AUTH:
                if offset + 2 > len(rest):
                    break
                nh_next, auth_len = struct.unpack(
                    "!BB", rest[offset:offset + 2],
                )
                offset += (auth_len + 2) * 4
                nh = nh_next
                continue
            break

        if offset + 2 > len(rest):
            break
        nh_next = rest[offset]
        hdr_ext_len = rest[offset + 1]
        offset += (hdr_ext_len + 1) * 8
        nh = nh_next

    l4 = rest[offset:]

    src_port: int | None = None
    dst_port: int | None = None

    if nh == PROTO_TCP and len(l4) >= 4 or nh == PROTO_UDP and len(l4) >= 4:
        src_port, dst_port = struct.unpack("!HH", l4[:4])

    record = _make_record(
        PacketRecord, ts, eth_src, eth_dst, ethertype, vlan_id,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        ip_proto=nh,
        payload=l4,
        length=total_length, raw=total_raw,
    )

    meta: dict[str, Any] = {
        "version": 6,
        "traffic_class": tclass,
        "flow_label": flow_label,
        "hop_limit": hop_limit,
        "payload_length": payload_len,
        "extension_chain": tuple(extension_chain),
        "is_fragment": is_fragment,
        "fragment_offset": fragment_offset,
        "fragment_id": fragment_id,
        "final_next_header": nh,
    }
    try:
        object.__setattr__(record, "ipv6_meta", meta)
    except (AttributeError, TypeError):
        pass

    return record


def _make_record(cls, ts, eth_src, eth_dst, ethertype, vlan_id,
                 src_ip, dst_ip, src_port=None, dst_port=None,
                 ip_proto=0, payload=b"", length=0, raw=b""):
    """Создать PacketRecord, устойчиво к отсутствию полей."""
    import dataclasses
    if dataclasses.is_dataclass(cls):
        fields = {f.name for f in dataclasses.fields(cls)}
        kwargs = {
            "ts": ts,
            "length": length,
            "raw": raw,
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "ethertype": ethertype,
            "vlan_id": vlan_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "ip_proto": ip_proto,
            "payload": payload,
        }
        filtered = {k: v for k, v in kwargs.items() if k in fields}
        return cls(**filtered)
    return cls()
