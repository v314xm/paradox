"""PNG-шевроны для QComboBox/QSpinBox, рисуются в temp при старте."""
from __future__ import annotations

import tempfile
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPen

from paradox_gui.theme.palette import PALETTE


def _chevron_png(path: Path, up: bool, color: str) -> None:
    """Нарисовать шеврон 2x: QSS уменьшает его до 9x6 (7x5 в спинбоксе)."""
    image = QImage(18, 12, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), 2.6)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    if up:
        painter.drawLine(4, 8, 9, 4)
        painter.drawLine(9, 4, 14, 8)
    else:
        painter.drawLine(4, 4, 9, 8)
        painter.drawLine(9, 8, 14, 4)
    painter.end()
    image.save(str(path), "PNG")


def _arrow_assets() -> dict[str, str]:
    """PNG-шевроны в temp: QSS не рисует треугольники без картинки."""
    directory = Path(tempfile.gettempdir()) / "paradox_theme"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        down_path = directory / "chevron-down-v1.png"
        up_path = directory / "chevron-up-v1.png"
        disabled_path = directory / "chevron-down-disabled-v2.png"
        if not down_path.exists():
            _chevron_png(down_path, up=False, color=PALETTE["text_muted"])
        if not up_path.exists():
            _chevron_png(up_path, up=True, color=PALETTE["text_muted"])
        if not disabled_path.exists():
            _chevron_png(
                disabled_path, up=False, color=PALETTE["text_muted"]
            )
    except OSError:
        return {}
    return {
        "arrow_down": str(down_path),
        "arrow_up": str(up_path),
        "arrow_down_disabled": str(disabled_path),
    }
