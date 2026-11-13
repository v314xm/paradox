"""Markdown-отчёт: timeline."""
from __future__ import annotations

from paradox.i18n import L
from paradox.reporters.markdown.format import (
    _escape_cell,
    _fmt_rel,
    _short,
)
from paradox.reporters.markdown.mitre import (
    _mitre_for_finding,
)


def _render_timeline(report: dict, top_n: int = 50) -> list[str]:
    """
    Хронология findings + contradictions по фазам kill-chain.

    v0.8.0: читаем report["timeline"] — плоский список событий,
    отсортированный по ts. Группируем по phase (kill-chain), внутри
    фазы — таблица событий. Fallback на старое поведение, если
    timeline в отчёте отсутствует.
    """
    timeline = report.get("timeline")
    if not timeline:
        return _render_timeline_fallback(report, top_n=15)

    lines: list[str] = ["## Timeline", ""]
    lines.append(
        L(
            "_Хронология findings и противоречий по фазам kill-chain. "
            "Время — относительно первого события._",
            "_Timeline of findings and contradictions by kill-chain phase. "
            "Time is relative to the first event._",
        )
    )
    lines.append("")

    # t0 — минимум ts среди всех событий.
    t0 = min(e.get("ts", 0.0) for e in timeline)

    # Группировка по phase, порядок фаз — по chain_order.
    by_phase: dict[str, list[dict]] = {}
    phase_order: dict[str, int] = {}
    for e in timeline:
        phase = e.get("phase", "other")
        by_phase.setdefault(phase, []).append(e)
        phase_order[phase] = e.get("chain_order", 999)

    ordered_phases = sorted(
        by_phase.keys(),
        key=lambda p: (phase_order.get(p, 999), p),
    )

    shown = 0
    for phase in ordered_phases:
        events = by_phase[phase]
        lines.append(f"### {phase} ({len(events)})")
        lines.append("")
        lines.append(
            L(
                "| Время (rel) | Kind | Тип | Subject | Описание | Conf | MITRE |",
                "| Time (rel) | Kind | Type | Subject | Description | Conf | MITRE |",
            )
        )
        lines.append("|---|---|---|---|---|---|---|")
        for e in events:
            if shown >= top_n:
                break
            rel = _fmt_rel(e.get("ts", 0.0) - t0)
            kind = e.get("kind", "?")
            etype = _escape_cell(e.get("type", "?"))
            subject = _escape_cell(_short(e.get("subject") or "?", 20))
            desc = _escape_cell(_short(e.get("description") or "", 70))
            conf = e.get("confidence", 0.0)
            mitre = e.get("mitre_id") or "—"
            lines.append(
                f"| {rel} | `{kind}` | `{etype}` | `{subject}` | "
                f"{desc} | {conf:.2f} | {mitre} |"
            )
            shown += 1
        lines.append("")
        if shown >= top_n:
            remaining = len(timeline) - shown
            if remaining > 0:
                lines.append(
                    L(
                        f"_…и ещё {remaining} событий — см. JSON-отчёт._",
                        f"_…and {remaining} more events — see the JSON report._",
                    )
                )
                lines.append("")
            break

    return lines


def _render_timeline_fallback(report: dict, top_n: int = 15) -> list[str]:
    """
    Fallback для отчётов без report["timeline"] (до v0.8.0).

    Плоская хронология findings по first_seen — как было раньше.
    """
    findings = report.get("findings", [])
    lines: list[str] = ["## Timeline", ""]

    with_ts = [f for f in findings if f.get("first_seen") is not None]
    if not with_ts:
        lines.append(L("_Нет timestamps у findings._", "_No timestamps on findings._"))
        lines.append("")
        return lines

    t0 = min(f["first_seen"] for f in with_ts)
    sorted_f = sorted(with_ts, key=lambda f: f["first_seen"])

    lines.append(
        L(
            "| Время (rel) | Тип | Значение | Conf | MITRE |",
            "| Time (rel) | Type | Value | Conf | MITRE |",
        )
    )
    lines.append("|---|---|---|---|---|")
    for f in sorted_f[:top_n]:
        rel = _fmt_rel(f["first_seen"] - t0)
        ftype = f.get("type", "?")
        value = _short(f.get("value", "?"), 60)
        conf = f.get("confidence", 0.0)
        mitre = _mitre_for_finding(f)
        lines.append(
            f"| {rel} | `{ftype}` | {value} | {conf:.2f} | {mitre} |"
        )
    if len(sorted_f) > top_n:
        lines.append(
            f"| ... | _({L('ещё', 'and')} {len(sorted_f) - top_n})_ | | | |"
        )
    lines.append("")
    return lines
