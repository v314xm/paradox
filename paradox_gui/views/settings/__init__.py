"""Вкладка «Настройки», разбитая по страницам.

view.py     — SettingsView: сигналы, каркас, поиск, загрузка/сохранение;
builders.py — общие строители форм;
constants.py — секции, детекторы, правила;
parsers.py  — разбор списков портов и строк;
pages/      — миксины по одной странице на модуль.
"""
from __future__ import annotations

from paradox_gui.views.settings.constants import (
    _CONTRADICTIONS,
    _DETECTORS,
    _SECTIONS,
)
from paradox_gui.views.settings.parsers import (
    _format_lines,
    _format_ports,
    _is_port_key,
    _parse_lines,
    _parse_ports,
    _parse_ports_with_report,
)
from paradox_gui.views.settings.view import SettingsView

__all__ = [
    "SettingsView",
    "_CONTRADICTIONS",
    "_DETECTORS",
    "_SECTIONS",
    "_format_lines",
    "_format_ports",
    "_is_port_key",
    "_parse_lines",
    "_parse_ports",
    "_parse_ports_with_report",
]
