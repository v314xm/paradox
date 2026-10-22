# tools/fix_23_unique_uris_count.py
"""Fix #23: unique_uris в HTTP-отчёте никогда не превышал top_n.

flow_report._http_report дедуплицировал URI в `seen`, но обрезал
список на top_n, а потом возвращал len(seen). На больших pcap с
500+ уникальных URI отчёт всегда показывал 100 (top_n).

Фикс: считаем полное множество независимо от обрезки для топа.
"""
from __future__ import annotations
from pathlib import Path

from fix_utils import patch, FixError, assert_applied

FIX_ID = "23-unique-uris-count"
TITLE = "http_report: unique_uris считает полное множество"

REL = "paradox/reporters/flow_report.py"

_OLD_BLOCK = """    # Уникальные URI: сортируем по bytes убыв., берём top_n
    # Дедуплицируем по (host, uri) — оставляем первый
    seen: set[tuple[str, str]] = set()
    unique_uris: list[dict] = []
    for u in sorted(uris, key=lambda x: -x["bytes"]):
        k = (u["host"], u["uri"])
        if k in seen:
            continue
        seen.add(k)
        unique_uris.append(u)
        if len(unique_uris) >= top_n:
            break"""

_NEW_BLOCK = """    # Полное множество (для поля unique_uris), не обрезанное top_n.
    all_unique_uris = {(u["host"], u["uri"]) for u in uris}
    # Топ — дедуплицированный список, обрезанный top_n.
    seen: set[tuple[str, str]] = set()
    unique_uris: list[dict] = []
    for u in sorted(uris, key=lambda x: -x["bytes"]):
        k = (u["host"], u["uri"])
        if k in seen:
            continue
        seen.add(k)
        unique_uris.append(u)
        if len(unique_uris) >= top_n:
            break"""

_OLD_FIELD = '        "unique_uris": len(seen),'
_NEW_FIELD = '        "unique_uris": len(all_unique_uris),'

_MARKER_BLOCK = "all_unique_uris = "
_MARKER_FIELD = "len(all_unique_uris)"


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL, _OLD_BLOCK, _NEW_BLOCK, required=False):
        changed = True
    if patch(root, REL, _OLD_FIELD, _NEW_FIELD, required=False):
        changed = True
    assert_applied(root, REL, _MARKER_BLOCK)
    assert_applied(root, REL, _MARKER_FIELD)
    return changed