"""Ошибки границ Paradox.

Отдельный модуль, чтобы CLI и GUI могли отличать «пользователь дал
не тот файл» от внутренней ошибки, не импортируя pipeline целиком.
"""
from __future__ import annotations


class ParadoxInputError(Exception):
    """Входной файл нельзя прочитать как pcap."""
