"""
ContradictionDetector — слой анализа поверх findings.

Ищет не атаки, а несогласованности между источниками данных:
одно и то же утверждение о мире подтверждается одним источником
и опровергается другим.

Пример: X — victim (brute_force dst) и attacker (lateral src).
Одна из интерпретаций неверна, либо X — pivot.

Публичный API:
    from paradox.contradictions import run_all
    contradictions = run_all(state, findings, config)
"""
from paradox.contradictions.base import (
    Contradiction,
    ContradictionRule,
    Fact,
)
from paradox.contradictions.registry import RULES, run_all

__all__ = [
    "RULES",
    "Contradiction",
    "ContradictionRule",
    "Fact",
    "run_all",
]