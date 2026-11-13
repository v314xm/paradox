"""Логотип Paradox: единый источник графики.

Всё рисуется кодом через QPainter — никаких внешних PNG/SVG.
Иконка приложения, шапка главного окна, About, пустые состояния.
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRect, Qt
from PySide6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPen,
    QPixmap,
    QRadialGradient,
)

_ACCENT = "#5b8cff"
_ACCENT_LIGHT = "#8bb0ff"
_BG_INNER = "#2a2d3a"
_BG_OUTER = "#1a1a26"


def render_logo(size: int) -> QPixmap:
    """Отрисовать логотип-иконку (круг с ∞) размером size×size."""
    size = max(8, int(size))
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)

    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

    margin = max(1, size // 24)
    rect = QRect(margin, margin, size - 2 * margin, size - 2 * margin)

    # Радиальный градиент фона
    grad = QRadialGradient(size / 2, size / 2, size / 2)
    grad.setColorAt(0.0, QColor(_BG_INNER))
    grad.setColorAt(1.0, QColor(_BG_OUTER))
    p.setBrush(grad)
    p.setPen(QPen(QColor(_ACCENT), max(1.0, size / 48)))
    p.drawEllipse(rect)

    # ∞ — две окружности с перекрытием
    cx, cy = size / 2.0, size / 2.0
    r = size * 0.20
    offset = size * 0.13

    pen_w = max(1.2, size * 0.055)
    pen = QPen(QColor(_ACCENT_LIGHT), pen_w)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)

    # Левая и правая доли
    p.drawEllipse(QPointF(cx - offset, cy), r, r)
    p.drawEllipse(QPointF(cx + offset, cy), r, r)

    p.end()
    return pm


def get_app_icon() -> QIcon:
    """Иконка приложения с несколькими размерами."""
    icon = QIcon()
    for sz in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(render_logo(sz))
    return icon
