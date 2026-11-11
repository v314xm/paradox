"""Форматирование чисел для GUI: байты и счётчики."""
from __future__ import annotations

from paradox_gui.i18n import tr

_UNIT_KEYS = (
    ("unit.byte", 0),
    ("unit.kb", 0),
    ("unit.mb", 1),
    ("unit.gb", 1),
    ("unit.tb", 1),
)


def fmt_bytes(n: int) -> str:
    """2 КБ / 180.0 МБ — единицы берутся из словаря языка."""
    value = float(n)
    for key, decimals in _UNIT_KEYS:
        if value < 1024:
            unit = tr(key)
            if decimals == 0:
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} {tr('unit.pb')}"


def fmt_count(n: int) -> str:
    """Тысячи через пробел: 184233 читается хуже, чем 184 233."""
    return f"{int(n):,}".replace(",", " ")
