"""Markdown-отчёт: tldr."""
from __future__ import annotations

from paradox.reporters.markdown.format import (
    _short,
)
from paradox.reporters.markdown.iocs import (
    _chain_for,
    _pick_first_with_role,
)


def _render_tldr(report: dict) -> list[str]:
    """Короткий TL;DR: что произошло, кто атакует, что скачано."""
    findings = report.get("findings", [])
    entities = report.get("entities", {})
    internal = entities.get("internal", [])
    carved = report.get("carved_files", {}).get("files", [])
    contradictions = report.get("contradictions") or []

    lines: list[str] = ["## TL;DR", ""]

    if not findings and not contradictions:
        lines.append("_Findings нет. Трафик выглядит чистым на уровне эвристик._")
        lines.append("")
        return lines

    attacker = _pick_first_with_role(internal, "attacker_candidate")
    victim = _pick_first_with_role(internal, "victim_candidate")
    pivot = _pick_first_with_role(internal, "pivot")

    # Основное предложение — цепочка в порядке kill-chain.
    types = _chain_for(findings)
    types_str = " → ".join(f"`{t}`" for t in types) if types else "—"

    if pivot:
        lines.append(
            f"**PIVOT:** `{pivot}` — скомпрометирован и атакует дальше. "
            f"Типы: {types_str}."
        )
    elif attacker and victim:
        lines.append(
            f"**Инцидент:** `{attacker}` атакует `{victim}`. "
            f"Типы: {types_str}."
        )
    elif victim:
        lines.append(f"**Жертва:** `{victim}`. Типы: {types_str}.")
    elif attacker:
        lines.append(f"**Атакующий:** `{attacker}`. Типы: {types_str}.")
    else:
        lines.append(f"**Findings:** {types_str}.")
    lines.append("")

    # Ключевое — список
    if pivot:
        lines.append(f"- **Pivot:** `{pivot}` (внутренний, критично)")
    if attacker:
        lines.append(f"- Attacker: `{attacker}` (internal)")
    if victim:
        lines.append(f"- Victim: `{victim}` (internal)")

    # Payloads
    for f in carved[:3]:
        uri = f.get("uri", "?")
        size = f.get("size", 0)
        sha = (f.get("sha256") or "")[:16]
        ext = f.get("ext") or "?"
        lines.append(
            f"- Payload: `{uri}` ({ext}, {size} B, sha256 `{sha}…`)"
        )
    if len(carved) > 3:
        lines.append(f"- _(ещё {len(carved) - 3} payload'ов — см. Carved Files)_")

    # High-confidence findings
    high = [f for f in findings if f.get("confidence", 0) >= 0.85]
    if high:
        lines.append("")
        lines.append(f"**High-confidence ({len(high)}):**")
        for f in high[:5]:
            ftype = f.get("type", "?")
            value = _short(f.get("value", "?"), 70)
            lines.append(f"- `{ftype}` — `{value}` ({f.get('confidence', 0):.2f})")

    # Contradictions, если есть — короткая ссылка на секцию.
    if contradictions:
        lines.append("")
        lines.append(
            f"**Противоречия:** {len(contradictions)} — см. секцию ниже."
        )

    lines.append("")
    return lines
