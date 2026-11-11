"""Совместимый фасад Markdown-отчёта.

Реализация — в пакете paradox.reporters.markdown. Импорт из этого
модуля сохранён: json_reporter и GUI вызывают render_markdown, а
тесты патчат атрибут этого модуля.
"""
from __future__ import annotations

from paradox.reporters.markdown import render_markdown

__all__ = ["render_markdown"]
