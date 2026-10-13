"""
Извлечение фактов из CaptureState + Findings.

Факты — атомарные утверждения (source, subject, predicate, value).
Правила работают с фактами, не с findings напрямую: так проще
тестировать и комбинировать источники (finding + flow + dns).

Ключевая идея: значение (`value`) — необязательно. Если находка
говорит «X атакует кого-то» (port_scan по десяткам хостов) или
«X резолвит DGA» (nxdomain_burst — множество несозданных доменов),
конкретный контр-субъект неизвестен. Роль — известна. Правило
victim_makes_attack проверяет subject, а не value: pivot остаётся
pivot'ом и без точного адресата.
"""
from __future__ import annotations

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.base import Fact


# Типы findings, где src АТАКУЕТ dst. Полярность: src = attacker, dst = victim.
# Синхронизировано с entities.py (блок role_tags).
_ATTACK_TYPES: frozenset[str] = frozenset({
    "brute_force",
    "ftp_brute_force",
    "vulnerable_path",
    "command_injection",
    "port_scan",
    "web_scanner",
    "lateral_movement",
})

# Типы findings, где src — ЖЕРТВА (или инициатор), dst — C2/exfil-получатель.
# suspicious_port: internal src стучится на C2 dst — src жертва, не атакующий.
_VICTIM_SIGNAL_TYPES: frozenset[str] = frozenset({
    "beaconing",
    "dns_tunneling",
    "script_download",
    "nxdomain_burst",
    "ja3_malware",
    "sni_without_dns",
    "dga_domain",
    "cloud_tunnel",
    "ip_check_service",
    "typosquatting",
    "suspicious_port",
})


def _ts(f: Finding) -> float:
    return f.first_seen if f.first_seen is not None else 0.0


def extract_attack_facts(findings: list[Finding]) -> list[Fact]:
    """
    Факты victim_of / attacker_of из findings.

    Полярность:
      _ATTACK_TYPES       src→dst: attacker_of(src, dst) + victim_of(dst, src)
      _VICTIM_SIGNAL_TYPES src→dst: victim_of(src, dst) + attacker_of(dst, src)
      large_transfer       — по evidence.direction

    Отсутствующая сторона → value="". Например, port_scan не привязан
    к одной цели, nxdomain_burst не привязан к одному домену.
    В этих случаях фиксируем роль, но без контр-субъекта.
    """
    facts: list[Fact] = []

    for f in findings:
        ev = f.evidence or {}
        src = ev.get("src_ip")
        dst = ev.get("dst_ip")

        if f.type in _ATTACK_TYPES:
            if src:
                facts.append(Fact(
                    source="finding", subject=src,
                    predicate="attacker_of", value=dst or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "attacker"},
                ))
            if dst:
                facts.append(Fact(
                    source="finding", subject=dst,
                    predicate="victim_of", value=src,
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "victim"},
                ))

        elif f.type in _VICTIM_SIGNAL_TYPES:
            if src:
                facts.append(Fact(
                    source="finding", subject=src,
                    predicate="victim_of", value=dst or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "victim"},
                ))
            if dst:
                facts.append(Fact(
                    source="finding", subject=dst,
                    predicate="attacker_of", value=src,
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "c2"},
                ))

        elif f.type == "large_transfer":
            # direction — источник правды, вычислен в LargeTransferDetector.
            # outbound (internal → external): src жертва, утекает.
            # inbound  (external → internal): dst жертва, скачивает payload.
            # internal ↔ internal — не C2-канал, факт не генерим.
            direction = ev.get("direction")
            if direction == "outbound" and src:
                facts.append(Fact(
                    source="finding", subject=src,
                    predicate="victim_of", value=dst or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={
                        "finding_type": f.type, "role": "victim_exfil",
                    },
                ))
            elif direction == "inbound" and dst:
                facts.append(Fact(
                    source="finding", subject=dst,
                    predicate="victim_of", value=src or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={
                        "finding_type": f.type, "role": "victim_ingress",
                    },
                ))

    return facts


def extract_facts(
    state: CaptureState,
    findings: list[Finding],
    config: Config,
) -> list[Fact]:
    """Общая точка входа: attack-факты из findings + ARP-факты из state."""
    _ = config
    return extract_attack_facts(findings) + extract_arp_facts(state)

def _mac_confidence(count: int) -> float:
    """
    Уверенность в факте «этот MAC реально принадлежит этому IP».

    1 пакет — 0.5 (может быть gratuitous ARP, спуф-выброс, случайный).
    ≥5 пакетов — 0.9 (устойчивое присутствие, реальный хост).
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

    Confidence растёт с count: одноразовое появление — 0.5,
    стабильное (≥5 пакетов) — 0.9. Правило mac_ip_conflict
    сравнивает два MAC на одном IP и берёт min из их confidence.
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