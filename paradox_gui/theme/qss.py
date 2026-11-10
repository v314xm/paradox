"""Сборка QSS из двух частей шаблона.

Обе части форматируются одними и теми же подстановками, поэтому
разделение на qss_global/qss_widgets не влияет на результат.
"""
from __future__ import annotations

from pathlib import Path

from paradox_gui.theme.palette import (
    MONO_FAMILY,
    PALETTE,
    SEVERITY,
    UI_FAMILY,
)
from paradox_gui.theme.qss_global import QSS_GLOBAL
from paradox_gui.theme.qss_widgets import QSS_WIDGETS


def _url(path: Path | str | None) -> str:
    return f'url("{Path(path).as_posix()}")' if path else "none"


def _placeholders(
    arrow_down: Path | str | None = None,
    arrow_up: Path | str | None = None,
    arrow_down_disabled: Path | str | None = None,
) -> dict[str, str]:
    return {
        "arrow_down": _url(arrow_down),
        "arrow_up": _url(arrow_up),
        "arrow_down_disabled": _url(arrow_down_disabled or arrow_down),
        "ui": UI_FAMILY,
        "mono": MONO_FAMILY,
        "critical": SEVERITY["critical"],
        "high": SEVERITY["high"],
        "medium": SEVERITY["medium"],
        "low": SEVERITY["low"],
        "info": SEVERITY["info"],
        **PALETTE,
    }


def build_qss(
    arrow_down: Path | str | None = None,
    arrow_up: Path | str | None = None,
    arrow_down_disabled: Path | str | None = None,
) -> str:
    """Собрать QSS. Пути к стрелкам подставляются при старте приложения."""
    values = _placeholders(arrow_down, arrow_up, arrow_down_disabled)
    return QSS_GLOBAL.format(**values) + QSS_WIDGETS.format(**values)


#: QSS без сгенерированных стрелок — для тестов и как fallback.
QSS = build_qss()
