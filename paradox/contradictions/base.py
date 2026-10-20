"""
Базовые типы contradictions.

Fact          — атомарное утверждение об объекте из одного источника.
Contradiction — согласованно зафиксированное противоречие между фактами.
Rule Protocol — контракт правила.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from paradox.config import Config
from paradox.models import CaptureState, Finding

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}


@dataclass(frozen=True)
class Fact:
    """
    Атомарное утверждение о мире из одного источника.

    source     — "dns" | "sni" | "http_host" | "ja3" | "arp" |
                 "kerberos" | "finding" | "flow"
    subject    — о ком: IP, домен, MAC
    predicate  — что утверждается:
                 "resolves_to" | "connects_to" | "uses_tls_stack" |
                 "victim_of"   | "attacker_of"
    value      — значение предиката
    ts         — timestamp (обычно first_seen)
    confidence — надёжность источника, 0..1
    evidence   — сырые данные для отчёта
    """
    source: str
    subject: str
    predicate: str
    value: str
    ts: float
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Contradiction:
    """
    Найденная несогласованность между фактами.

    Это не finding: мета-наблюдение над findings. По желанию
    конвертируется в synthetic Finding для build_entities.
    """
    rule: str
    subject: str
    facts: list[Fact]
    severity: str
    confidence: float
    likely_causes: list[str] = field(default_factory=list)
    resolution_hint: str | None = None

    @property
    def priority(self) -> float:
        """severity × confidence. Чем выше — тем раньше показать."""
        return SEVERITY_WEIGHT.get(self.severity, 0.0) * self.confidence

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "subject": self.subject,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "priority": round(self.priority, 3),
            "likely_causes": list(self.likely_causes),
            "resolution_hint": self.resolution_hint,
            "facts": [
                {
                    "source": f.source,
                    "subject": f.subject,
                    "predicate": f.predicate,
                    "value": f.value,
                    "ts": f.ts,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                }
                for f in self.facts
            ],
        }


@runtime_checkable
class ContradictionRule(Protocol):
    """Контракт правила. Реализации — в contradictions/rules/."""

    name: str
    severity_base: str

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        ...

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        ...
