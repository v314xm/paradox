"""NDP (Neighbor Discovery Protocol) экстрактор.

Работает поверх PacketRecord, который вернул IPv6-парсер.
Извлекает NDP-сообщения:
  - RS (133) / RA (134) — роутеры
  - NS (135) / NA (136) — соседи (аналог ARP)
  - Redirect (137) — перенаправления

Опции (TLV) парсятся выборочно:
  - Type 1: Source Link-Layer Address (MAC отправителя)
  - Type 2: Target Link-Layer Address (MAC цели)
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass
class NdpRecord:
    ts: float
    src_ip: str
    dst_ip: str
    icmp_type: int
    kind: str  # "rs" | "ra" | "ns" | "na" | "redirect"
    target_ip: str | None = None
    target_mac: str | None = None
    source_mac: str | None = None
    is_router: bool = False
    is_solicited: bool = False
    is_override: bool = False


def extract_ndp(record) -> NdpRecord | None:
    """Извлечь NDP-данные из PacketRecord."""
    if getattr(record, "ip_proto", None) != 58:
        return None

    payload = getattr(record, "payload", b"")
    if len(payload) < 4:
        return None

    icmp_type = payload[0]
    if icmp_type not in (133, 134, 135, 136, 137):
        return None

    kinds = {133: "rs", 134: "ra", 135: "ns", 136: "na", 137: "redirect"}
    kind = kinds[icmp_type]

    target_ip = None
    target_mac = None
    source_mac = None
    is_router = False
    is_solicited = False
    is_override = False

    # NS (135), NA (136) и Redirect (137) имеют Target Address на смещении 8
    if icmp_type in (135, 136, 137) and len(payload) >= 24:
        target_ip = str(ipaddress.IPv6Address(payload[8:24]))

        # Флаги актуальны только для NA (136)
        if icmp_type == 136:
            flags = payload[4]
            is_router = bool(flags & 0x80)
            is_solicited = bool(flags & 0x40)
            is_override = bool(flags & 0x20)

    # Правильные смещения для опций (TLV):
    # RS (133) = 8 байт
    # RA (134) = 16 байт (Type, Code, Chksum, CurHop, Flags, Lifetime, Reach, Retrans)
    # NS (135), NA (136) = 24 байта (Type, Code, Chksum, Flags, Reserved, TargetIP)
    # Redirect (137) = 40 байт (Type, Code, Chksum, Reserved, TargetIP, DestIP)
    opt_offsets = {133: 8, 134: 16, 135: 24, 136: 24, 137: 40}
    opt_offset = opt_offsets.get(icmp_type, len(payload))

    while opt_offset + 2 <= len(payload):
        opt_type = payload[opt_offset]
        opt_len = payload[opt_offset + 1] * 8  # длина в 8-байтных блоках

        if opt_len == 0 or opt_offset + opt_len > len(payload):
            break

        # Type 1: Source Link-Layer Address
        if opt_type == 1 and opt_len >= 8:
            source_mac = payload[opt_offset + 2:opt_offset + 8].hex(":")
        # Type 2: Target Link-Layer Address
        elif opt_type == 2 and opt_len >= 8:
            target_mac = payload[opt_offset + 2:opt_offset + 8].hex(":")

        opt_offset += opt_len

    return NdpRecord(
        ts=record.ts,
        src_ip=record.src_ip or "",
        dst_ip=record.dst_ip or "",
        icmp_type=icmp_type,
        kind=kind,
        target_ip=target_ip,
        target_mac=target_mac,
        source_mac=source_mac,
        is_router=is_router,
        is_solicited=is_solicited,
        is_override=is_override,
    )


class NDPExtractor:
    """Экстрактор NDP для потокового пайплайна."""
    name = "ndp"

    def process(self, record, state) -> None:
        ndp = extract_ndp(record)
        if not ndp:
            return

        # Инициализация структур в state при первом NDP-пакете
        if not hasattr(state, "ndp_neighbors"):
            state.ndp_neighbors = {}
        if not hasattr(state, "ndp_routers"):
            state.ndp_routers = set()
        if not hasattr(state, "ndp_total"):
            state.ndp_total = 0

        state.ndp_total += 1

        if ndp.kind == "na" and ndp.target_ip and ndp.target_mac:
            state.ndp_neighbors[ndp.target_ip] = ndp.target_mac
        elif ndp.kind == "ns" and ndp.target_ip and ndp.source_mac:
            if ndp.target_ip not in state.ndp_neighbors:
                state.ndp_neighbors[ndp.target_ip] = ndp.source_mac
        elif ndp.kind == "ra" and ndp.src_ip:
            state.ndp_routers.add(ndp.src_ip)
