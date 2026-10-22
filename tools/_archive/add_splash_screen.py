"""Splash screen при старте GUI."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPLASH = REPO_ROOT / "paradox_gui" / "splash.py"
APP = REPO_ROOT / "paradox_gui" / "app.py"


SPLASH_PY = r'''"""Красивый splash screen при старте Paradox GUI.

Рисуется целиком кодом (QPainter), без внешних картинок —
чтобы .exe остался самодостаточным. Тёмная тема, логотип,
версия, прогресс-бар, статусы загрузки.
"""
from __future__ import annotations

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import (
    QColor, QFont, QLinearGradient, QPainter, QPen, QPixmap,
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

        # Заполнение
        if self._progress > 0:
            painter.setBrush(QColor("#5b8cff"))
            fill_w = max(1, int(bar_w * self._progress))
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
'''


NEW_APP_MAIN = '''def main() -> int:
    app = QApplication(sys.argv)

    # Splash ДО тяжёлых импортов (main_window тянет все views)
    splash = ParadoxSplash()
    splash.show()
    app.processEvents()

    # 1. Ключи Threat Intel из keyring -> os.environ
    splash.set_status("Загрузка ключей Threat Intel…")
    splash.set_progress(0.15)
    app.processEvents()
    try:
        from paradox_gui.secrets_store import SecretsStore
        SecretsStore().apply_all_to_env()
    except Exception:
        pass

    # 2. Тема
    splash.set_status("Применение тёмной темы…")
    splash.set_progress(0.35)
    app.processEvents()
    apply_theme(app)

    # 3. Тяжёлый импорт + сборка главного окна
    splash.set_status("Инициализация ядра и модулей…")
    splash.set_progress(0.55)
    app.processEvents()
    from paradox_gui.main_window import MainWindow
    w = MainWindow()

    # 4. Показ
    splash.set_status("Готово")
    splash.set_progress(1.0)
    app.processEvents()
    w.showMaximized()
    splash.finish(w)
    return app.exec()
'''


def main() -> int:
    print("=" * 60)
    print(" add splash screen")
    print("=" * 60)

    # 1. Создать splash.py
    if SPLASH.exists():
        print(f"[SKIP] {SPLASH.relative_to(REPO_ROOT)} exists")
    else:
        SPLASH.write_text(SPLASH_PY, encoding="utf-8")
        print(f"[OK] created {SPLASH.relative_to(REPO_ROOT)}")

    # 2. Патч app.py
    if not APP.exists():
        print(f"[ERROR] {APP} not found", file=sys.stderr)
        return 1

    src = APP.read_text(encoding="utf-8")

    if "ParadoxSplash" in src and "splash.finish" in src:
        print("[SKIP] app.py already uses splash")
        return 0

    # Заменить импорт main_window на импорт splash
    old_import = "from paradox_gui.main_window import MainWindow\n"
    new_import = "from paradox_gui.splash import ParadoxSplash\n"
    if old_import in src:
        src = src.replace(old_import, new_import, count=1)
        print("[OK] main_window import → splash import (lazy)")

    # Заменить старую main()
    start = src.find("def main() -> int:")
    if start < 0:
        print("[ERROR] def main() not found in app.py", file=sys.stderr)
        return 2
    end = src.find("\n\nif __name__", start)
    if end < 0:
        # Файл может заканчиваться на main без if __name__
        end = len(src)

    # Если MainWindow не импортирован лениво внутри main — надо это учесть
    if "from paradox_gui.main_window import MainWindow" not in NEW_APP_MAIN:
        pass  # в NEW_APP_MAIN импорт есть внутри функции — правильный lazy-import

    src = src[:start] + NEW_APP_MAIN + src[end:]
    APP.write_text(src, encoding="utf-8")
    print("[OK] app.py main() rewritten with splash")

    # 3. Проверка импорта
    print("\nVerifying import...")
    sys.path.insert(0, str(REPO_ROOT))
    import importlib
    try:
        import paradox_gui.splash
        importlib.reload(paradox_gui.splash)
        print("[OK] paradox_gui.splash imports")

        import paradox_gui.app
        importlib.reload(paradox_gui.app)
        print("[OK] paradox_gui.app imports")
    except Exception as e:
        print(f"[ERROR] import failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
