"""Объяснения находок человеческим языком.

Публичный API:
    from paradox.explain import explain_finding, explain_contradiction

    exp = explain_finding(finding_dict)      # dict или объект Finding
    exp.to_dict()                            # для JSON-отчёта и GUI

Ключевой принцип: объяснение — это данные, а не вёрстка. Модалка
находки, Markdown-отчёт и JSON показывают один и тот же текст.
Покрытие типов держит тест `tests/test_explain.py`: новый тип находки
без объяснения валит прогон так же, как отсутствие MITRE-маппинга.
"""
from __future__ import annotations

from paradox.explain.catalog import FINDING_SPECS
from paradox.explain.contradiction_catalog import RULE_SPECS
from paradox.explain.model import Explanation, TypeSpec
from paradox.explain.render import (
    build_context,
    confidence_note,
    facts_summary,
    phase_label,
    render,
)
from paradox.taxonomy import get_techniques

__all__ = [
    "FINDING_SPECS",
    "RULE_SPECS",
    "Explanation",
    "TypeSpec",
    "explain_contradiction",
    "explain_finding",
    "explanation_for",
]


def _as_dict(item) -> dict:
    """Принять dict из отчёта или объект с to_dict()."""
    if isinstance(item, dict):
        return item
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise TypeError(
        f"ожидался dict или объект с to_dict(), получено {type(item)!r}"
    )


def _fallback_finding_spec(finding: dict) -> TypeSpec:
    return TypeSpec(
        headline="Сработал детектор «{type}»: {value}.",
        why=(
            "Для этого типа нет заготовленного объяснения — обычно так "
            "бывает у детекторов-плагинов. Смотрите на фазу и техники, "
            "оценивайте сырые значения в evidence."
        ),
        next_steps=(
            "Откройте пакеты этого потока и убедитесь, что событие реальное.",
            "Сверьте адрес с инвентарём: свой ли это узел и ожидаемый ли порт.",
        ),
        beginner=(
            "Детектор сработал по неизвестному нам шаблону. Это повод "
            "посмотреть трафик руками, а не готовый вывод."
        ),
    )


def _fallback_rule_spec(contradiction: dict) -> TypeSpec:
    return TypeSpec(
        headline=(
            "Источники расходятся по {subject}: {facts}."
        ),
        why=(
            "Противоречие означает, что два независимых источника "
            "описывают узел по-разному. Один из них ошибается или "
            "видит другую часть картины."
        ),
        next_steps=(
            "Сравните оба факта с сырыми пакетами.",
            "Проверьте, не NAT/прокси ли меняет представление.",
        ),
        beginner=(
            "Два разных наблюдения не сходятся между собой. "
            "Это не приговор, а место, где нужно разобраться."
        ),
    )


def explain_finding(finding) -> Explanation:
    """Объяснить находку. Принимает dict отчёта или объект Finding."""
    data = _as_dict(finding)
    ftype = str(data.get("type") or "")
    spec = FINDING_SPECS.get(ftype) or _fallback_finding_spec(data)
    ctx = build_context(data)
    return Explanation(
        headline=render(spec.headline, ctx),
        why=render(spec.why, ctx),
        next_steps=tuple(render(s, ctx) for s in spec.next_steps),
        alternatives=tuple(render(s, ctx) for s in spec.alternatives),
        confidence_note=confidence_note(data.get("confidence")),
        beginner=render(spec.beginner, ctx),
        phase=phase_label(ftype),
        techniques=tuple(get_techniques(ftype)),
    )


def explain_contradiction(contradiction) -> Explanation:
    """Объяснить противоречие.

    «Что произошло» берём из `resolution_hint`: правило уже написало
    прозу с конкретными значениями и направлением. Шаблон из каталога —
    запасной путь для правил без hint.

    Альтернативные интерпретации берём из `likely_causes` — правило уже
    сформулировало их при создании противоречия, дублировать текст в
    каталоге не нужно.
    """
    data = _as_dict(contradiction)
    rule = str(data.get("rule") or "")
    spec = RULE_SPECS.get(rule) or _fallback_rule_spec(data)
    ctx = {
        "rule": rule,
        "subject": str(data.get("subject") or "—"),
        "facts": facts_summary(data) or "—",
        "conf": f"{data.get('confidence')}",
        "severity": str(data.get("severity") or "—"),
    }
    hint = str(data.get("resolution_hint") or "").strip()
    causes = tuple(str(c) for c in (data.get("likely_causes") or ()))
    alternatives = causes or tuple(
        render(s, ctx) for s in spec.alternatives
    )
    return Explanation(
        headline=hint or render(spec.headline, ctx),
        why=render(spec.why, ctx),
        next_steps=tuple(render(s, ctx) for s in spec.next_steps),
        alternatives=alternatives,
        confidence_note=confidence_note(data.get("confidence")),
        beginner=render(spec.beginner, ctx),
        phase="",
        techniques=(),
    )


def explanation_for(row) -> Explanation:
    """Объяснение из строки отчёта, с расчётом на месте при отсутствии.

    Отчёты, сохранённые до 2026-11-12 (история прогонов, ручные JSON),
    ключа `explanation` не содержат. Окно объяснений не должно из-за
    этого показывать пустоту: считаем тем же API, что и pipeline.

    Вид строки определяется по данным, а не по вызывающему коду:
    противоречие — это `rule` без `type`.
    """
    data = _as_dict(row)
    stored = data.get("explanation")
    if isinstance(stored, dict) and stored.get("headline"):
        return Explanation.from_dict(stored)
    if "rule" in data and "type" not in data:
        return explain_contradiction(data)
    return explain_finding(data)
