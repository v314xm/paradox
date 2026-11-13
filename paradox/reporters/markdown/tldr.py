"""Markdown-отчёт: tldr."""
from __future__ import annotations

from paradox.i18n import L
from paradox.reporters.markdown.format import (
    _short,
)
from paradox.reporters.markdown.iocs import (
    _chain_for,
    _pick_first_with_role,
)


def _linked(attacker: str, victim: str, findings: list[dict]) -> bool:
    """Есть ли находка, связывающая атакующего и жертву напрямую."""
    for f in findings:
        src, dst = f.get("src_ip"), f.get("dst_ip")
        if src == attacker and dst == victim:
            return True
        if src == victim and dst == attacker:
            return True
        if src == attacker:
            dsts = (f.get("evidence") or {}).get("top_dsts") or ()
            if any(
                isinstance(d, dict) and d.get("ip") == victim
                for d in dsts
            ):
                return True
    return False


def _render_tldr(report: dict) -> list[str]:
    """Короткий TL;DR: что произошло, кто атакует, что скачано."""
    findings = report.get("findings", [])
    entities = report.get("entities", {})
    internal = entities.get("internal", [])
    carved = report.get("carved_files", {}).get("files", [])
    contradictions = report.get("contradictions") or []

    lines: list[str] = ["## TL;DR", ""]

    if not findings and not contradictions:
        lines.append(
            L(
                "_Findings нет. Трафик выглядит чистым на уровне эвристик._",
                "_No findings. The traffic looks clean at the heuristic level._",
            )
        )
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
            L(
                f"**PIVOT:** `{pivot}` — скомпрометирован и атакует дальше. "
                f"Типы: {types_str}.",
                f"**PIVOT:** `{pivot}` — compromised and attacking onwards. "
                f"Types: {types_str}.",
            )
        )
    elif attacker and victim:
        # «Атакует» — только при прямой связи в находках. Иначе это
        # два независимых участника захвата, и утверждение было бы
        # домыслом (атакующий из port_scan и жертва C2 не связаны).
        if _linked(attacker, victim, findings):
            lines.append(
                L(
                    f"**Инцидент:** `{attacker}` атакует `{victim}`. "
                    f"Типы: {types_str}.",
                    f"**Incident:** `{attacker}` attacks `{victim}`. "
                    f"Types: {types_str}.",
                )
            )
        else:
            lines.append(
                L(
                    f"**Участники:** атакующий `{attacker}`, жертва "
                    f"`{victim}` — прямой связи между ними в находках нет. "
                    f"Типы: {types_str}.",
                    f"**Participants:** attacker `{attacker}`, victim "
                    f"`{victim}` — no direct link between them in the "
                    f"findings. Types: {types_str}.",
                )
            )
    elif victim:
        lines.append(
            L(
                f"**Жертва:** `{victim}`. Типы: {types_str}.",
                f"**Victim:** `{victim}`. Types: {types_str}.",
            )
        )
    elif attacker:
        lines.append(
            L(
                f"**Атакующий:** `{attacker}`. Типы: {types_str}.",
                f"**Attacker:** `{attacker}`. Types: {types_str}.",
            )
        )
    else:
        lines.append(f"**Findings:** {types_str}.")
    lines.append("")

    # Ключевое — список
    if pivot:
        lines.append(
            L(
                f"- **Pivot:** `{pivot}` (внутренний, критично)",
                f"- **Pivot:** `{pivot}` (internal, critical)",
            )
        )
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
        lines.append(
            L(
                f"- _(ещё {len(carved) - 3} payload'ов — см. Carved Files)_",
                f"- _({len(carved) - 3} more payloads — see Carved Files)_",
            )
        )

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
            L(
                f"**Противоречия:** {len(contradictions)} — см. секцию ниже.",
                f"**Contradictions:** {len(contradictions)} — see the section below.",
            )
        )

    lines.append("")
    return lines
