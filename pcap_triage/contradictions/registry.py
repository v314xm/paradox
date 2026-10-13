"""
Реестр правил contradictions.

run_all прогоняет все правила, извлекает факты per-rule и
собирает Contradiction'ы в единый сортированный список.

Факты извлекаются для каждого правила отдельно — это дороже по CPU,
но правило не зависит от чужих фактов и легко тестируется изолированно.
При росте числа правил >10 — перейти на батч-извлечение.
"""
from __future__ import annotations

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.rules.b_mac_ip_conflict import (
    MacIpConflictRule,
)
from pcap_triage.contradictions.base import (
    Contradiction,
    ContradictionRule,
    SEVERITY_ORDER,
)
from pcap_triage.contradictions.rules.e_victim_makes_attack import (
    VictimMakesAttackRule,
)


RULES: list[ContradictionRule] = [
    VictimMakesAttackRule(),
    MacIpConflictRule(),
]


def run_all(
    state: CaptureState,
    findings: list[Finding],
    config: Config,
) -> list[Contradiction]:
    """Прогнать все правила. Возвращает отфильтрованные + отсортированные."""
    out: list[Contradiction] = []
    for rule in RULES:
        facts = rule.extract_facts(state, findings, config)
        out.extend(rule.find_contradictions(facts))

    out.sort(key=lambda c: (
        SEVERITY_ORDER.get(c.severity, 99),
        -c.confidence,
        c.subject,
    ))
    return out