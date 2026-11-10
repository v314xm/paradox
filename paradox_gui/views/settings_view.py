"""Совместимый фасад вкладки «Настройки».

Реализация разбита на пакет paradox_gui.views.settings: страницы,
парсеры и константы. Импорт из этого модуля сохранён, чтобы не менять
main_window и тесты.
"""
from __future__ import annotations

from paradox_gui.views.settings import (
    _CONTRADICTIONS,
    _DETECTORS,
    _SECTIONS,
    SettingsView,
    _format_lines,
    _format_ports,
    _is_port_key,
    _parse_lines,
    _parse_ports,
    _parse_ports_with_report,
)

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
