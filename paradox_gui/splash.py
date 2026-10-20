"""Красивый splash screen при старте Paradox GUI.

Рисуется целиком кодом (QPainter), без внешних картинок —
чтобы .exe остался самодостаточным. Тёмная тема, логотип,
версия, прогресс-бар, статусы загрузки.
"""
from __future__ import annotations

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import (
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import QSplashScreen

try:
    from paradox_gui import __version__ as GUI_VERSION
except ImportError:
    GUI_VERSION = "1.0.0"


class ParadoxSplash(QSplashScreen):
    """Кастомный splash: тёмный градиент, логотип, прогресс-бар."""

    WIDTH = 640
    HEIGHT = 400

    def __init__(self) -> None:
        pixmap = self._render_static()
        super().__init__(
            pixmap,
            Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.FramelessWindowHint,
        )
        self._status = "Загрузка…"
        self._progress = 0.0

    def _render_static(self) -> QPixmap:
        pm = QPixmap(self.WIDTH, self.HEIGHT)
        pm.fill(Qt.GlobalColor.transparent)

        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Градиентный фон
        grad = QLinearGradient(0, 0, self.WIDTH, self.HEIGHT)
        grad.setColorAt(0.0, QColor("#1e1e2e"))
        grad.setColorAt(0.5, QColor("#282a36"))
        grad.setColorAt(1.0, QColor("#1a1a26"))
        p.fillRect(0, 0, self.WIDTH, self.HEIGHT, grad)

        # Верхний акцент — тонкая голубая линия
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#5b8cff"))
        p.drawRect(0, 0, self.WIDTH, 3)

        # Тонкая рамка
        p.setPen(QPen(QColor("#3a3d4d"), 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRect(0, 0, self.WIDTH - 1, self.HEIGHT - 1)

        # Логотип PARADOX
        p.setPen(QColor("#5b8cff"))
        font = QFont("Segoe UI", 42, QFont.Weight.Black)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 8)
        p.setFont(font)
        p.drawText(
            QRect(0, 70, self.WIDTH, 80),
            Qt.AlignmentFlag.AlignCenter,
            "PARADOX",
        )

        # Декоративный символ ∞ между словом и версией
        p.setPen(QColor("#3a3d4d"))
        p.setFont(QFont("Segoe UI", 14))
        p.drawText(
            QRect(0, 145, self.WIDTH, 20),
            Qt.AlignmentFlag.AlignCenter,
            "─── ∞ ───",
        )

        # Подзаголовок
        p.setPen(QColor("#a0a0b0"))
        p.setFont(QFont("Segoe UI", 11))
        p.drawText(
            QRect(0, 170, self.WIDTH, 30),
            Qt.AlignmentFlag.AlignCenter,
            "PCAP Triage · Kill-Chain · Threat Intel",
        )

        # Версия
        p.setPen(QColor("#6a6a7a"))
        p.setFont(QFont("Consolas", 9))
        p.drawText(
            QRect(0, 200, self.WIDTH, 20),
            Qt.AlignmentFlag.AlignCenter,
            f"v{GUI_VERSION}",
        )

        p.end()
        return pm

    # ---------- API ----------

    def set_status(self, text: str) -> None:
        """Обновить строку статуса под прогресс-баром."""
        self._status = text
        self.repaint()

    def set_progress(self, value: float) -> None:
        """value 0.0 .. 1.0 — заполнение прогресс-бара."""
        self._progress = max(0.0, min(1.0, value))
        self.repaint()

    # ---------- отрисовка поверх pixmap ----------

    def drawContents(self, painter: QPainter) -> None:  # noqa: N802
        bar_x = 80
        bar_y = self.HEIGHT - 80
        bar_w = self.WIDTH - 160
        bar_h = 6

        # Фон прогресс-бара
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#2a2d3a"))
        painter.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 3, 3)

        # Заполнение (с эффектом бегущего градиента)
        if self._progress > 0:
            fill_w = max(1, int(bar_w * self._progress))
            grad = QLinearGradient(bar_x, 0, bar_x + fill_w, 0)
            grad.setColorAt(0.0, QColor("#3a6ce0"))
            grad.setColorAt(0.5, QColor("#5b8cff"))
            grad.setColorAt(1.0, QColor("#8bb0ff"))
            painter.setBrush(grad)
            painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 3, 3)

        # Статус
        painter.setPen(QColor("#a0a0b0"))
        painter.setFont(QFont("Segoe UI", 10))
        painter.drawText(
            QRect(bar_x, bar_y + 18, bar_w, 25),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            self._status,
        )

        # Процент справа
        if self._progress > 0:
            painter.setPen(QColor("#6a6a7a"))
            painter.setFont(QFont("Consolas", 9))
            painter.drawText(
                QRect(bar_x, bar_y + 18, bar_w, 25),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{int(self._progress * 100)}%",
            )
