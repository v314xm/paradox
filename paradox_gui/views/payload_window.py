"""Отдельное окно «Код инжекта».

Просмотр выдержек payload'ов вынесен из вкладок: окно можно держать
рядом с основным, растянуть на второй монитор и не терять при
переключении вкладок отчёта.

Содержимое — тот же `PayloadView`; окно отвечает только за заголовок,
размер и передачу отчёта.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QVBoxLayout, QWidget

from paradox_gui.i18n import tr
from paradox_gui.views.payload_view import PayloadView


class PayloadWindow(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle(f"{tr('payload.title')} — Paradox")
        self.resize(1500, 860)
        self.setMinimumSize(980, 620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.view = PayloadView()
        layout.addWidget(self.view)

        self._report: dict | None = None

    def set_report(self, report: dict | None) -> None:
        """Передать отчёт: окно пересобирает список выдержек."""
        self._report = report
        self.view.update_data(report or {})

    def report(self) -> dict | None:
        return self._report

    def clear(self) -> None:
        self._report = None
        self.view.clear()
