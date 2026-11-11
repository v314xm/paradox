"""ARP, asymmetry, protocol-on-port и direct-IP факты.

Вынесено из ``facts.py``; обслуживает правила mac_ip_conflict,
reverse_asymmetry, port_service_mismatch и direct_ip_no_dns.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.contradictions.base import Fact
from paradox.models import CaptureState, make_session_key
from paradox.net_utils import is_internal_ip, is_public_ip

# =====================================================================
# ARP facts: история MAC на IP (для mac_ip_conflict)
# =====================================================================

def _mac_confidence(count: int) -> float:
    """
    Уверенность в факте «этот MAC реально принадлежит этому IP».

    Эвристика по числу ARP-пакетов от этого MAC на этом IP:
      1 пакет   — 0.5  (gratuitous ARP, спуф-выброс, случайный)
      2 пакета  — 0.6
      3–4       — 0.75
      ≥5        — 0.9  (устойчивое присутствие, реальный хост)

    Порог 5 — из практики: реальный хост за сессию отправляет десятки
    ARP, спуфер может выдать 1-2 поддельных до обнаружения.
    """
    if count >= 5:
        return 0.9
    if count >= 3:
        return 0.75
    if count >= 2:
        return 0.6
    return 0.5


def extract_arp_facts(state: CaptureState) -> list[Fact]:
    """
    Факты has_mac из ARP-истории: один Fact на уникальный (IP, MAC).

    Источник — `state.arp_macs`, который заполняет ARPMacHistoryExtractor.
    Отдельный от `host_identities` (там только последний MAC, для
    отчёта сущностей).

    Правило mac_ip_conflict группирует по subject (IP) и ищет
    несколько MAC. Одиночный MAC → правило молчит.

    evidence несёт first_ts / last_ts / count — по ним правило
    определяет пересечение окон (spoof vs lease change).
    """
    facts: list[Fact] = []
    for ip, macs in state.arp_macs.items():
        for mac, entry in macs.items():
            first_ts, last_ts, count = entry[0], entry[1], entry[2]
            facts.append(Fact(
                source="arp",
                subject=ip,
                predicate="has_mac",
                value=mac,
                ts=first_ts,
                confidence=_mac_confidence(count),
                evidence={
                    "first_ts": first_ts,
                    "last_ts": last_ts,
                    "count": count,
                },
            ))
    return facts


# =====================================================================
# Reverse asymmetry facts: пропорция трафика в сессии
# =====================================================================

def extract_asymmetry_facts(
    state: CaptureState,
    config: Config,
) -> list[Fact]:
    """
    Факты session_asymmetry: одна запись на internal ↔ external сессию.

    Группируем оба направления одного соединения (по make_session_key),
    суммируем байты относительно internal-стороны, считаем ratio.

    Что фильтруем:
      - сессии, где нет обеих сторон (только A→B без ответа);
      - internal ↔ internal и external ↔ external (там asymmetry
        не имеет смысла — нет «наружу»);
      - total_bytes < reverse_asymmetry_min_total_bytes.

    Что кладём в evidence:
      bytes_out / bytes_in — от internal-перспективы;
      ratio — max/min, при bytes_in == 0 → float("inf");
      external_ip, порты, proto — для hint'а в отчёте.

    Правило reverse_asymmetry решает severity по ratio — здесь
    только фильтр по абсолютному объёму.
    """
    # Ключ сессии → {ip: {"bytes": N, "port": P, "first": T, "last": T}}
    sessions: dict[tuple, dict[str, dict]] = {}

    for key, flow in state.flows.items():
        sk = make_session_key(key)
        bucket = sessions.setdefault(
            (sk.ip_lo, sk.port_lo, sk.ip_hi, sk.port_hi, sk.proto),
            {},
        )
        entry = bucket.setdefault(key.src_ip, {
            "bytes": 0, "port": key.src_port,
            "first": None, "last": None,
        })
        entry["bytes"] += flow.bytes_sent
        # first_ts и last_ts независимы: flow может иметь одно и не
        # иметь другого. Раньше last_ts сравнивался внутри проверки
        # first_ts и None ронял правило reverse_asymmetry целиком.
        if flow.first_ts is not None:
            if entry["first"] is None or flow.first_ts < entry["first"]:
                entry["first"] = flow.first_ts
        if flow.last_ts is not None:
            if entry["last"] is None or flow.last_ts > entry["last"]:
                entry["last"] = flow.last_ts

    facts: list[Fact] = []
    min_total = config.reverse_asymmetry_min_total_bytes

    for session_key, sides in sessions.items():
        # Односторонняя сессия: только один src_ip. Пропускаем —
        # сравнивать не с чем, а ratio=∞ породит FP.
        if len(sides) < 2:
            continue

        ips = list(sides.keys())
        a_ip, b_ip = ips[0], ips[1]
        a, b = sides[a_ip], sides[b_ip]

        a_internal = is_internal_ip(a_ip, config)
        b_internal = is_internal_ip(b_ip, config)

        # Ровно одна сторона внутренняя — иначе пропускаем.
        if a_internal and not b_internal:
            internal_ip, external_ip = a_ip, b_ip
            bytes_out, bytes_in = a["bytes"], b["bytes"]
            internal_port, external_port = a["port"], b["port"]
            internal_side, external_side = a, b
        elif b_internal and not a_internal:
            internal_ip, external_ip = b_ip, a_ip
            bytes_out, bytes_in = b["bytes"], a["bytes"]
            internal_port, external_port = b["port"], a["port"]
            internal_side, external_side = b, a
        else:
            continue

        total = bytes_out + bytes_in
        if total < min_total:
            continue

        # ratio = большая / меньшая. bytes_in == 0 → бесконечность
        # (односторонний исходящий канал).
        if bytes_in == 0:
            ratio = float("inf") if bytes_out > 0 else 1.0
        elif bytes_out == 0:
            ratio = float("inf")
        else:
            ratio = max(bytes_out, bytes_in) / min(bytes_out, bytes_in)

        # Timestamp начала сессии — из обеих сторон, берём min.
        firsts = [
            s["first"] for s in (internal_side, external_side)
            if s["first"] is not None
        ]
        ts_first = min(firsts) if firsts else 0.0

        facts.append(Fact(
            source="flow",
            subject=internal_ip,
            predicate="session_asymmetry",
            value=f"{bytes_out}/{bytes_in}",
            ts=ts_first,
            confidence=1.0,
            evidence={
                "external_ip": external_ip,
                "internal_port": internal_port,
                "external_port": external_port,
                "proto": session_key[4],
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "total_bytes": total,
                "ratio": ratio,
            },
        ))

    return facts
# =====================================================================
# Protocol-on-port facts: что реально ходит поверх порта
# =====================================================================

def extract_protocol_on_port_facts(
    state: CaptureState,
    config: Config,
) -> list[Fact]:
    """
    Факты protocol_on_port: одна запись на flow × распознанный протокол.

    Протокол детектируется только там, где у нас есть надёжный признак:
      "tls"  — flow.ja3 или flow.sni заполнены (TLSExtractor распарсил
               ClientHello). Сам факт ja3/sni уже означает, что в
               payload был TLS handshake.
      "http" — flow.http_method заполнен (HTTPExtractor распарсил
               первую строку как валидный HTTP-метод).

    Оба — не эвристики, а результат парсинга. Confidence = 0.95.

    Сессии без явного протокола (чистый TCP, UDP без наших
    экстракторов) не попадают — сравнивать нечего.

    Если на flow и TLS, и HTTP (HTTP/2-negotiation на том же
    соединении) — генерим два факта. Правило всё равно сгруппирует
    по (subject, dst_ip, dst_port).

    config сейчас не используется — сигнатура зафиксирована на будущее,
    чтобы добавление, например, allowlist'а не ломало callers.
    """
    _ = config

    facts: list[Fact] = []

    for key, flow in state.flows.items():
        if key.proto != "tcp":
            continue
        if key.dst_port is None:
            continue

        ts = flow.first_ts if flow.first_ts is not None else 0.0
        base_evidence = {
            "dst_ip": key.dst_ip,
            "dst_port": key.dst_port,
            "src_port": key.src_port,
        }

        if flow.ja3 or flow.sni:
            facts.append(Fact(
                source="tls",
                subject=key.src_ip,
                predicate="protocol_on_port",
                value="tls",
                ts=ts,
                confidence=0.95,
                evidence={
                    **base_evidence,
                    "sni": flow.sni,
                    "ja3": flow.ja3,
                },
            ))

        if flow.http_method:
            facts.append(Fact(
                source="http",
                subject=key.src_ip,
                predicate="protocol_on_port",
                value="http",
                ts=ts,
                confidence=0.95,
                evidence={
                    **base_evidence,
                    "method": flow.http_method,
                    "host": flow.http_host,
                    "uri": flow.http_uri,
                },
            ))

    return facts

# =====================================================================
# Direct-IP / DNS facts: hardcoded IP в обход DNS
# =====================================================================

def _looks_like_public_ip(ip: str, config: Config) -> bool:
    """Публичный адрес по единой классификации net_utils."""
    return is_public_ip(ip, config)


def extract_direct_ip_facts(
    state: CaptureState,
    config: Config,
) -> list[Fact]:
    """
    Факты direct_ip_connect и makes_dns_queries по клиенту (src_ip).

    direct_ip_connect — на каждый external IP, к которому клиент
    ходил. Группируем по (src_ip, dst_ip), не по flow, чтобы не
    плодить N фактов на один dst.

    makes_dns_queries — маркер «этот клиент вообще резолвит».
    Не привязываем к конкретному домену, потому что сопоставить
    DNS-ответ с flow мы не можем (нет A-записей). Значит — грубая,
    но работающая эвристика: «клиент с DNS-запросами» vs «клиент
    без DNS-запросов».

    Фильтр:
      - только external dst (внутренний обмен — не в зону правила);
      - min_bucket_size: пропускаем единичные flows — мусор.
    """
    # (src_ip, dst_ip) → набор портов, число flows + суммарные байты.
    buckets: dict[tuple[str, str], dict] = {}

    for key, flow in state.flows.items():
        if not _looks_like_public_ip(key.dst_ip, config):
            continue
        pair = (key.src_ip, key.dst_ip)
        b = buckets.setdefault(pair, {
            "ports": set(),
            "flows": 0,
            "bytes": 0,
            "first_ts": None,
        })
        if key.dst_port is not None:
            b["ports"].add(key.dst_port)
        b["flows"] += 1
        b["bytes"] += flow.bytes_sent
        if flow.first_ts is not None:
            if b["first_ts"] is None or flow.first_ts < b["first_ts"]:
                b["first_ts"] = flow.first_ts

    facts: list[Fact] = []
    for (src, dst), b in buckets.items():
        # resolved: был ли DNS-ответ для этого dst_ip в этом захвате.
        # Если да — это не hardcoded IP, правило direct_ip_no_dns
        # должно молчать. Точность per-IP вместо старого «клиент
        # вообще делал DNS-запросы» (слишком широкий фильтр).
        resolved = dst in state.dns_answers_by_ip
        facts.append(Fact(
            source="flow",
            subject=src,
            predicate="direct_ip_connect",
            value=dst,
            ts=b["first_ts"] or 0.0,
            confidence=0.9,
            evidence={
                "dst_ip": dst,
                "ports": sorted(b["ports"]),
                "flows": b["flows"],
                "bytes_sent": b["bytes"],
                "resolved": resolved,
            },
        ))

    # Маркеры: клиент X сделал ≥1 DNS-запрос.
    for client_ip, counter in state.dns_queries_by_src.items():
        total = sum(counter.values())
        if total == 0:
            continue
        facts.append(Fact(
            source="dns",
            subject=client_ip,
            predicate="makes_dns_queries",
            value="",
            ts=0.0,
            confidence=0.9,
            evidence={
                "count": total,
                "sample": sorted(counter.keys())[:5],
            },
        ))

    return facts
