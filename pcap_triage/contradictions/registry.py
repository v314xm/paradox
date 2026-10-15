"""
Реестр правил contradictions.
"""
from __future__ import annotations

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.rules.g_direct_ip_no_dns import (
    DirectIpNoDnsRule,
)
from pcap_triage.contradictions.rules.e_reverse_asymmetry import (
    ReverseAsymmetryRule,
)
from pcap_triage.contradictions.rules.f_port_service_mismatch import (
    PortServiceMismatchRule,
)
from pcap_triage.contradictions.rules.d_ja3_ua_mismatch import (
    Ja3UaMismatchRule,
)
from pcap_triage.contradictions.base import (
    Contradiction,
    ContradictionRule,
    SEVERITY_ORDER,
)
from pcap_triage.contradictions.rules.a_sni_without_dns import (
    SniWithoutDnsRule,
)
from pcap_triage.contradictions.rules.e_victim_makes_attack import (
    VictimMakesAttackRule,
)
from pcap_triage.contradictions.rules.b_mac_ip_conflict import (
    MacIpConflictRule,
)
from pcap_triage.contradictions.rules.c_sni_host_mismatch import (
    SniHostMismatchRule,
)


# Контракт: правила STATELESS. extract_facts / find_contradictions
# чистые функции от аргументов. Если появится stateful правило —
# заменить список на фабрику build_rules() и вызывать в run_all().
RULES: list[ContradictionRule] = [
    SniWithoutDnsRule(),
    VictimMakesAttackRule(),
    MacIpConflictRule(),
    SniHostMismatchRule(),
    Ja3UaMismatchRule(),
    ReverseAsymmetryRule(),
    PortServiceMismatchRule(),
    DirectIpNoDnsRule(),
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