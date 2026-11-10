"""Наложение QSS на QApplication."""
from __future__ import annotations

from PySide6.QtWidgets import QApplication

from paradox_gui.theme.assets import _arrow_assets
from paradox_gui.theme.qss import build_qss


def apply_theme(app: QApplication) -> None:
    """Накладывает QSS на QApplication. Вызывать один раз при старте."""
    app.setStyleSheet(build_qss(**_arrow_assets()))
