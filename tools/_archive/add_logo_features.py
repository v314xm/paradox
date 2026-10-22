"""Logo features: icon, header, About, empty-state watermark."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGO = REPO_ROOT / "paradox_gui" / "logo.py"
APP = REPO_ROOT / "paradox_gui" / "app.py"
MAIN = REPO_ROOT / "paradox_gui" / "main_window.py"
RUN_VIEW = REPO_ROOT / "paradox_gui" / "views" / "run_view.py"


LOGO_PY = r'''"""Логотип Paradox: единый источник графики.

Всё рисуется кодом через QPainter — никаких внешних PNG/SVG.
Иконка приложения, шапка главного окна, About, пустые состояния.
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRect, Qt
from PySide6.QtGui import (
    QColor, QIcon, QLinearGradient, QPainter, QPainterPath,
    QPen, QPixmap, QRadialGradient,
)
from PySide6.QtWidgets import QLabel


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


def logo_label(size: int = 24) -> QLabel:
    """Готовый QLabel с логотипом (для шапки окна)."""
    lbl = QLabel()
    lbl.setPixmap(render_logo(size))
    lbl.setFixedSize(size, size)
    lbl.setStyleSheet("background: transparent;")
    return lbl


def wordmark_pixmap(width: int = 480, height: int = 120) -> QPixmap:
    """Широкая логотип-плашка: иконка + слово PARADOX.

    Для splash, About, пустых состояний.
    """
    pm = QPixmap(width, height)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Иконка слева
    icon_size = min(height - 20, height)
    icon_pm = render_logo(icon_size)
    p.drawPixmap(10, (height - icon_size) // 2, icon_pm)

    # Текст справа
    from PySide6.QtGui import QFont
    font = QFont("Segoe UI", int(height * 0.35), QFont.Weight.Black)
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 6)
    p.setFont(font)
    p.setPen(QColor(_ACCENT))
    text_x = icon_size + 30
    p.drawText(
        QRect(text_x, 0, width - text_x - 10, height),
        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
        "PARADOX",
    )
    p.end()
    return pm
'''


def create_logo_module() -> bool:
    if LOGO.exists():
        print(f"[SKIP] {LOGO.relative_to(REPO_ROOT)} exists")
        return True
    LOGO.write_text(LOGO_PY, encoding="utf-8")
    print(f"[OK] created {LOGO.relative_to(REPO_ROOT)}")
    return True


def _patch(path: Path, old: str, new: str, name: str) -> bool:
    src = path.read_text(encoding="utf-8")
    if new in src and old not in src:
        print(f"[SKIP] {name}: already applied")
        return True
    if old not in src:
        print(f"[ERROR] {name}: anchor not found in {path.name}", file=sys.stderr)
        return False
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


# =========================================================
# 1. app.py: setWindowIcon
# =========================================================
def patch_app_icon() -> bool:
    old = (
        'def main() -> int:\n'
        '    app = QApplication(sys.argv)\n'
    )
    new = (
        'def main() -> int:\n'
        '    app = QApplication(sys.argv)\n'
        '    # Иконка приложения (taskbar + title bar)\n'
        '    try:\n'
        '        from paradox_gui.logo import get_app_icon\n'
        '        app.setWindowIcon(get_app_icon())\n'
        '    except Exception:\n'
        '        pass\n'
    )
    return _patch(APP, old, new, "app.py: setWindowIcon")


# =========================================================
# 2. main_window.py: лого в шапке + иконка окна
# =========================================================
def patch_header_logo() -> bool:
    old = (
        '        container = QWidget()\n'
        '        vbox = QVBoxLayout(container)\n'
        '        vbox.setContentsMargins(0, 0, 0, 0)\n'
        '        vbox.setSpacing(0)\n'
        '        vbox.addWidget(self._topmenu)\n'
        '        vbox.addWidget(self.tabs, stretch=1)\n'
        '        self.setCentralWidget(container)\n'
    )
    new = (
        '        # Шапка: логотип + меню\n'
        '        try:\n'
        '            from paradox_gui.logo import logo_label, get_app_icon\n'
        '            _logo = logo_label(24)\n'
        '            self.setWindowIcon(get_app_icon())\n'
        '        except Exception:\n'
        '            _logo = None\n'
        '\n'
        '        header = QWidget()\n'
        '        header_h = QHBoxLayout(header)\n'
        '        header_h.setContentsMargins(10, 4, 4, 0)\n'
        '        header_h.setSpacing(6)\n'
        '        if _logo is not None:\n'
        '            header_h.addWidget(_logo)\n'
        '        header_h.addWidget(self._topmenu, stretch=1)\n'
        '\n'
        '        container = QWidget()\n'
        '        vbox = QVBoxLayout(container)\n'
        '        vbox.setContentsMargins(0, 0, 0, 0)\n'
        '        vbox.setSpacing(0)\n'
        '        vbox.addWidget(header)\n'
        '        vbox.addWidget(self.tabs, stretch=1)\n'
        '        self.setCentralWidget(container)\n'
    )
    return _patch(MAIN, old, new, "main_window: header with logo")


def patch_about_dialog() -> bool:
    """Заменить QMessageBox в _on_about на кастомный QDialog с логотипом."""
    # Найдём весь блок _on_about и заменим
    src = MAIN.read_text(encoding="utf-8")
    start = src.find("    def _on_about(self) -> None:")
    if start < 0:
        print("[ERROR] _on_about not found", file=sys.stderr)
        return False
    # Конец: следующий def на том же уровне
    end = src.find("\n    def ", start + 10)
    if end < 0:
        end = len(src)

    new_method = '''    def _on_about(self) -> None:
        """About-диалог с логотипом."""
        try:
            from PySide6.QtWidgets import (
                QDialog, QDialogButtonBox, QLabel, QVBoxLayout,
            )
            from paradox_gui.logo import render_logo

            dlg = QDialog(self)
            dlg.setWindowTitle("О программе")
            dlg.setMinimumWidth(420)
            v = QVBoxLayout(dlg)
            v.setContentsMargins(24, 24, 24, 16)
            v.setSpacing(10)

            # Логотип по центру
            logo_lbl = QLabel()
            logo_lbl.setPixmap(render_logo(96))
            logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.addWidget(logo_lbl)

            # Заголовок
            title = QLabel(f"Paradox v{APP_VERSION}")
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title.setStyleSheet(
                "font-size: 20px; font-weight: 700; color: #5b8cff;"
            )
            v.addWidget(title)

            subtitle = QLabel("Оффлайн-триаж pcap")
            subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            subtitle.setObjectName("muted")
            v.addWidget(subtitle)

            # Модули — сетка
            modules = QLabel(
                "<div style='text-align:center; line-height:1.6;'>"
                "<span style='color:#e0e0e0;'>"
                "20 детекторов · 12 правил<br>"
                "4 экстрактора · 4 анализатора<br>"
                "</span>"
                "<span style='color:#a0a0b0; font-size:11px;'>"
                "Attack Graph · Multi-pcap · Threat Intel<br>"
                "Shodan · AbuseIPDB · VirusTotal · OTX · URLScan"
                "</span></div>"
            )
            modules.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.addWidget(modules)

            # Разделитель
            sep = QLabel("─" * 30)
            sep.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sep.setStyleSheet("color: #3a3d4d;")
            v.addWidget(sep)

            # Копирайт
            copyright_lbl = QLabel("© 2026 Andrey Grigoryev (v314xm)")
            copyright_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            copyright_lbl.setObjectName("muted")
            v.addWidget(copyright_lbl)

            # Кнопка закрыть
            btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            btn.rejected.connect(dlg.reject)
            btn.button(QDialogButtonBox.StandardButton.Close).setText("Закрыть")
            v.addWidget(btn)

            dlg.exec()
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(
                self, "О программе — ошибка", f"{type(e).__name__}: {e}",
            )

'''

    new_src = src[:start] + new_method + src[end:]
    MAIN.write_text(new_src, encoding="utf-8")
    print("[OK] main_window: About dialog with logo")
    return True


# =========================================================
# 3. run_view.py: watermark в пустом состоянии
# =========================================================
def patch_empty_watermark() -> bool:
    """Добавить полупрозрачный логотип в drop zone, пока нет прогона."""
    old = (
        '        self._icon = QLabel("📁")\n'
        '        self._icon.setStyleSheet("font-size: 32px;")\n'
        '        self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)\n'
    )
    # Это в drop_zone.py, не run_view.py
    dz = REPO_ROOT / "paradox_gui" / "widgets" / "drop_zone.py"
    if not dz.exists():
        print("[SKIP] empty watermark: drop_zone.py not found")
        return True

    src = dz.read_text(encoding="utf-8")
    if "render_logo" in src:
        print("[SKIP] empty watermark: already applied")
        return True

    if old not in src:
        print("[ERROR] empty watermark: anchor not found", file=sys.stderr)
        return False

    new = (
        '        # Логотип вместо эмодзи папки (v1.2)\n'
        '        try:\n'
        '            from paradox_gui.logo import render_logo\n'
        '            self._icon = QLabel()\n'
        '            self._icon.setPixmap(render_logo(64))\n'
        '            self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)\n'
        '        except Exception:\n'
        '            self._icon = QLabel("📁")\n'
        '            self._icon.setStyleSheet("font-size: 32px;")\n'
        '            self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)\n'
    )
    dz.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print("[OK] drop_zone: logo instead of folder emoji")
    return True


def main() -> int:
    print("=" * 60)
    print(" add logo features")
    print("=" * 60)
    ok = True
    for fn in (
        create_logo_module,
        patch_app_icon,
        patch_header_logo,
        patch_about_dialog,
        patch_empty_watermark,
    ):
        try:
            if not fn():
                ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False

    # Проверка импорта
    print("\nVerifying imports...")
    sys.path.insert(0, str(REPO_ROOT))
    import importlib
    for modname in ("paradox_gui.logo", "paradox_gui.app", "paradox_gui.main_window"):
        try:
            m = importlib.import_module(modname)
            importlib.reload(m)
            print(f"[OK] {modname}")
        except Exception as e:
            print(f"[ERROR] {modname}: {type(e).__name__}: {e}", file=sys.stderr)
            ok = False

    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
