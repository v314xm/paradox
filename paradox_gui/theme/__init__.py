"""Стиль Paradox: палитра, QSS и его применение.

Пакет разбит по назначению:
  palette.py      — цвета и шрифты (единственный источник правды);
  qss_global.py   — базовые правила (фон, меню, вкладки, контролы);
  qss_widgets.py  — служебные классы и виджет-специфичные правила;
  qss.py          — сборка QSS из двух частей;
  assets.py       — PNG-шевроны в temp;
  apply.py        — наложение на QApplication.

При добавлении стилей помните: в шаблоне литеральные CSS-блоки
пишутся как {{ ... }}, иначе .format() примет их за подстановку.
Новые секции — в конец qss_widgets.py.
"""
from __future__ import annotations

from paradox_gui.theme.apply import apply_theme
from paradox_gui.theme.assets import _arrow_assets
from paradox_gui.theme.palette import (
    MONO_FAMILY,
    PALETTE,
    SEVERITY,
    UI_FAMILY,
)
from paradox_gui.theme.qss import QSS, build_qss

__all__ = [
    "MONO_FAMILY",
    "PALETTE",
    "QSS",
    "SEVERITY",
    "UI_FAMILY",
    "_arrow_assets",
    "apply_theme",
    "build_qss",
]
