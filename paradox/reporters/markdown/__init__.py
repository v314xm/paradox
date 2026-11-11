"""Markdown-отчёт, разбитый по назначению.

format.py   — форматтеры чисел, длительностей и ячеек;
mitre.py    — MITRE-подписи для findings;
iocs.py     — извлечение IOC и порядок kill-chain;
tldr.py     — блок TL;DR;
timeline.py — хронология и её fallback;
sections.py — таблицы, сущности, HTTP, отсутствие, NDP, сертификаты;
document.py — сборка итогового документа.
"""
from __future__ import annotations

from paradox.reporters.markdown.document import render_markdown

__all__ = ["render_markdown"]
