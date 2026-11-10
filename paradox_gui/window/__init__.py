"""Главное окно Paradox, разбитое по частям.

window.py    — MainWindow: каркас, вкладки, статус-бар, closeEvent;
menus.py     — меню, фабрика действий, тёмный заголовок;
actions.py   — обработчики файлов, анализа и обогащения;
export.py    — экспорт JSON/Markdown/connections;
shortcuts.py — Esc/фуллскрин и кириллические варианты шорткатов.
"""
from __future__ import annotations

from paradox_gui.window.shortcuts import _cyr_variant
from paradox_gui.window.window import (
    TAB_TITLE_KEYS,
    TAB_TITLES,
    ClickableLabel,
    MainWindow,
)

__all__ = [
    "TAB_TITLE_KEYS",
    "TAB_TITLES",
    "ClickableLabel",
    "MainWindow",
    "_cyr_variant",
]
