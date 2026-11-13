"""Role/behavior факты для правила role_deviation.

Один ``assigned_role`` факт на внутренний хост с известной ролью + один
``observed_behavior`` факт на каждое наблюдаемое поведение. Правило
``role_deviation`` сопоставляет их по subject.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.contradictions.base import Fact
from paradox.host_profiler import HostProfiler, internal_hosts
from paradox.models import CaptureState


def extract_role_facts(
    state: CaptureState,
    config: Config,
) -> list[Fact]:
    """Факты assigned_role + observed_behavior по внутренним хостам."""
    profiler = HostProfiler()
    facts: list[Fact] = []

    for ip in sorted(internal_hosts(state, config)):
        role = profiler.assign_role(state, config, ip)
        # Без базовой роли (неизвестный OUI) отклонение не с чем
        # сравнивать — факт assigned_role не создаём, правило молчит.
        if role == "unknown":
            continue

        facts.append(Fact(
            source="role_profile",
            subject=ip,
            predicate="assigned_role",
            value=role,
            ts=0.0,
            confidence=0.9,
            evidence=profiler.role_evidence(state, ip),
        ))

        for behavior, ev in profiler.observe_behaviors(state, config, ip).items():
            facts.append(Fact(
                source="behavior",
                subject=ip,
                predicate="observed_behavior",
                value=behavior,
                ts=ev.get("first_ts") or 0.0,
                confidence=0.9,
                evidence=ev,
            ))

    return facts
