"""Markdown-отчёт: раздел «Интерпретация».

Тот же текст, что в GUI-окне объяснений и в JSON: `Explanation.to_markdown()`
из `paradox.explain`. Отдельный раздел нужен потому, что отчёт читают в
тикете — без него таблица findings остаётся списком голых полей.

Старые отчёты без ключа `explanation` поддерживаются: `explanation_for`
считает текст на месте.
"""
from __future__ import annotations

from paradox.explain import explanation_for
from paradox.i18n import L
from paradox.reporters.markdown.format import _short
from paradox.reporters.markdown.sections import _SEVERITY_ICON

#: Больше — отчёт превращается в простыню; остальное остаётся в JSON и GUI.
_MAX_ENTRIES = 20


def _render_interpretation(report: dict) -> list[str]:
    findings = report.get("findings") or []
    contradictions = report.get("contradictions") or []
    if not findings and not contradictions:
        return []

    entries: list[tuple[str, dict]] = [
        ("finding", f) for f in findings
    ] + [("contradiction", c) for c in contradictions]

    lines: list[str] = [L("## Интерпретация", "## Interpretation"), ""]
    lines.append(
        L(
            "_Что произошло, почему это важно и куда смотреть — тот же текст, "
            "что в окне объяснений._",
            "_What happened, why it matters and where to look — the same text "
            "as in the explanation window._",
        )
    )
    lines.append("")

    for kind, row in entries[:_MAX_ENTRIES]:
        severity = row.get("severity", "info")
        icon = _SEVERITY_ICON.get(severity, "·")

        if kind == "finding":
            ftype = str(row.get("type") or "?")
            value = _short(str(row.get("value") or "—"), 80)
            lines.append(f"### {icon} `{ftype}` — `{value}`")
        else:
            rule = str(row.get("rule") or "?")
            subject = _short(str(row.get("subject") or "—"), 80)
            lines.append(
                f"### {icon} {L('Противоречие', 'Contradiction')} "
                f"`{rule}` — `{subject}`"
            )
        lines.append("")

        text = explanation_for(row).to_markdown()
        if text:
            lines.extend(text.splitlines())
            lines.append("")

    hidden = len(entries) - _MAX_ENTRIES
    if hidden > 0:
        lines.append(
            L(
                f"_Ещё {hidden} записей без интерпретации — смотрите JSON-отчёт "
                "или окно объяснений._",
                f"_{hidden} more entries without interpretation — see the JSON "
                "report or the explanation window._",
            )
        )
        lines.append("")

    return lines
