"""Совместимый фасад главного окна.

Реализация — в пакете paradox_gui.window (меню, действия, экспорт,
шорткаты, каркас окна). Импорт из этого модуля сохранён для app.py и
tools/docs_inventory.py.
"""
from __future__ import annotations

from paradox_gui.window import (
    TAB_TITLE_KEYS,
    TAB_TITLES,
    ClickableLabel,
    MainWindow,
    _cyr_variant,
)

__all__ = [
    "TAB_TITLE_KEYS",
    "TAB_TITLES",
    "ClickableLabel",
    "MainWindow",
    "_cyr_variant",
]
