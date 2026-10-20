"""
Реестр правил contradictions.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.contradictions.base import (
    SEVERITY_ORDER,
    Contradiction,
    ContradictionRule,
)
from paradox.contradictions.rules.a_sni_without_dns import (
    SniWithoutDnsRule,
)
from paradox.contradictions.rules.b_mac_ip_conflict import (
    MacIpConflictRule,
)
from paradox.contradictions.rules.c_sni_host_mismatch import (
    SniHostMismatchRule,
)
from paradox.contradictions.rules.d_ja3_ua_mismatch import (
    Ja3UaMismatchRule,
)
from paradox.contradictions.rules.e_reverse_asymmetry import (
    ReverseAsymmetryRule,
)
from paradox.contradictions.rules.e_victim_makes_attack import (
    VictimMakesAttackRule,
)
from paradox.contradictions.rules.f_port_service_mismatch import (
    PortServiceMismatchRule,
)
from paradox.contradictions.rules.g_direct_ip_no_dns import (
    DirectIpNoDnsRule,
)
from paradox.contradictions.rules.h_dns_answer_mismatch import (
    DnsAnswerMismatchRule,
)
from paradox.contradictions.rules.i_sni_cert_mismatch import (
    SniCertMismatchRule,
)
from paradox.contradictions.rules.j_self_signed_cert import (
    SelfSignedCertRule,
)
from paradox.contradictions.rules.k_expired_cert import (
    ExpiredCertRule,
)
from paradox.models import CaptureState, Finding

# Контракт: правила STATELESS. extract_facts / find_contradictions
# чистые функции от аргументов. Если появится stateful правило —
# заменить список на фабрику build_rules() и вызывать в run_all().
RULES: list[ContradictionRule] = [
    SniWithoutDnsRule(),
    DnsAnswerMismatchRule(),
    SniCertMismatchRule(),
    SelfSignedCertRule(),
    ExpiredCertRule(),
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
