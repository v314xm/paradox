"""Attack facts: кто кого атакует по findings.

Вынесено из ``facts.py``; полярность задаётся один раз в
``paradox/taxonomy.py``.
"""
from __future__ import annotations

from paradox.contradictions.base import Fact
from paradox.models import Finding
from paradox.taxonomy import SRC_ROLE_BY_TYPE

# =====================================================================
# Attack facts: кто кого атакует по findings
# =====================================================================

# Полярность задаётся один раз в paradox/taxonomy.py.
# src = attacker, dst = victim для _ATTACK_TYPES;
# src = victim, dst = C2/exfil-получатель для _VICTIM_SIGNAL_TYPES.
_ATTACK_TYPES = frozenset(
    t for t, role in SRC_ROLE_BY_TYPE.items() if role == "attacker"
)
_VICTIM_SIGNAL_TYPES = frozenset(
    t for t, role in SRC_ROLE_BY_TYPE.items() if role == "victim"
)


def _ts(f: Finding) -> float:
    """Timestamp для факта. 0.0 — если у finding нет first_seen."""
    return f.first_seen if f.first_seen is not None else 0.0


def extract_attack_facts(findings: list[Finding]) -> list[Fact]:
    """
    Факты victim_of / attacker_of из findings.

    Полярность:
      _ATTACK_TYPES        src→dst: attacker_of(src, dst) + victim_of(dst, src)
      _VICTIM_SIGNAL_TYPES src→dst: victim_of(src, dst) + attacker_of(dst, src)
      large_transfer        — по evidence.direction

    Отсутствующая сторона → value="". Например, port_scan не привязан
    к одной цели (их десятки), nxdomain_burst — не к одному домену.
    В этих случаях фиксируем роль, но без контр-субъекта: правило
    victim_makes_attack проверяет subject, ему value не нужен.
    """
    facts: list[Fact] = []

    for f in findings:
        ev = f.evidence or {}
        # v0.9.0: top-level поля заполняются в Finding.__post_init__.
        src = f.src_ip
        dst = f.dst_ip

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
            # internal ↔ internal: не C2-канал, факт не генерим.
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
