"""Fix #25: compare_requested = Signal(object) объявлен дважды в HistoryView."""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError, assert_applied

FIX_ID = "25-drop-dup-compare-signal"
TITLE = "history_view: убрать дубль compare_requested"

REL = "paradox_gui/views/history_view.py"

_OLD = """    # Сигнал для запроса сравнения выбранного прогона с текущим.
    # Передаёт словарь report из истории.
    compare_requested = Signal(object)

    # Сигнал для запроса сравнения выбранного прогона с текущим.
    # Передаёт словарь report из истории.
    compare_requested = Signal(object)"""

_NEW = """    # Сигнал для запроса сравнения выбранного прогона с текущим.
    # Передаёт словарь report из истории.
    compare_requested = Signal(object)"""


def apply(root: Path) -> bool:
    changed = patch(root, REL, _OLD, _NEW, required=False)
    assert_applied(root, REL, "compare_requested = Signal")
    if not fix_utils.DRY_RUN:
        n = (root / REL).read_text(encoding="utf-8").count(
            "compare_requested = Signal"
        )
        if n != 1:
            raise FixError(f"{REL}: expected 1 signal, found {n}")
    return changed