"""Branding: clickable logo, statusbar credits, markdown footer."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MAIN_WINDOW = REPO_ROOT / "paradox_gui" / "main_window.py"
MARKDOWN = REPO_ROOT / "paradox" / "reporters" / "markdown_reporter.py"
SPLASH = REPO_ROOT / "paradox_gui" / "splash.py"


def _patch(path, old, new, name):
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


def patch_main_window():
    """Делаем логотип в шапке и статус-бар кликабельными."""
    src = MAIN_WINDOW.read_text(encoding="utf-8")

    # 1. Добавляем кастомный кликабельный лейбл в конец импортов
    if "class ClickableLabel(QLabel):" not in src:
        old_imports_end = "APP_VERSION = \"1.0.0\"\n"
        new_imports_end = (
            "APP_VERSION = \"1.0.0\"\n"
            "\n"
            "class ClickableLabel(QLabel):\n"
            "    from PySide6.QtCore import Signal\n"
            "    clicked = Signal()\n"
            "    def mousePressEvent(self, event):\n"
            "        if event.button() == Qt.MouseButton.LeftButton:\n"
            "            self.clicked.emit()\n"
            "        super().mousePressEvent(event)\n"
        )
        if old_imports_end in src:
            src = src.replace(old_imports_end, new_imports_end, count=1)
            print("[OK] main_window: ClickableLabel class added")

    # 2. Шапка: делаем лого кликабельным
    old_logo = (
        '        try:\n'
        '            from paradox_gui.logo import logo_label, get_app_icon\n'
        '            _logo = logo_label(24)\n'
        '            self.setWindowIcon(get_app_icon())\n'
        '        except Exception:\n'
        '            _logo = None\n'
    )
    new_logo = (
        '        try:\n'
        '            from paradox_gui.logo import render_logo, get_app_icon\n'
        '            self.setWindowIcon(get_app_icon())\n'
        '            _logo = ClickableLabel()\n'
        '            _logo.setPixmap(render_logo(24))\n'
        '            _logo.setFixedSize(24, 24)\n'
        '            _logo.setCursor(Qt.CursorShape.PointingHandCursor)\n'
        '            _logo.setToolTip("О программе")\n'
        '            _logo.clicked.connect(self._on_about)\n'
        '        except Exception:\n'
        '            _logo = None\n'
    )
    if old_logo in src:
        src = src.replace(old_logo, new_logo, count=1)
        print("[OK] main_window: clickable header logo")

    # 3. Статус-бар: заменяем QLabel на кликабельный
    old_status = '        sb.addPermanentWidget(QLabel(f"Версия: {APP_VERSION}"))\n'
    new_status = (
        '        self._version_lbl = ClickableLabel(f"v{APP_VERSION} · © v314xm")\n'
        '        self._version_lbl.setStyleSheet("color: #a0a0b0; padding: 0 8px;")\n'
        '        self._version_lbl.setCursor(Qt.CursorShape.PointingHandCursor)\n'
        '        self._version_lbl.setToolTip("О программе")\n'
        '        self._version_lbl.clicked.connect(self._on_about)\n'
        '        sb.addPermanentWidget(self._version_lbl)\n'
    )
    if old_status in src:
        src = src.replace(old_status, new_status, count=1)
        print("[OK] main_window: clickable status bar")

    MAIN_WINDOW.write_text(src, encoding="utf-8")


def patch_markdown():
    """Добавляем футер с автором в Markdown-отчёт."""
    old = (
        '    lines.append("---")\n'
        '    lines.append("")\n'
        '    lines.append("_Отчёт сгенерирован автоматически. Проверяй findings глазами: "\n'
        '                 "эвристики дают кандидатов, не приговоры._")\n'
        '    lines.append("")\n'
    )
    new = (
        '    lines.append("---")\n'
        '    lines.append("")\n'
        '    lines.append("_Отчёт сгенерирован автоматически. Проверяй findings глазами: "\n'
        '                 "эвристики дают кандидатов, не приговоры._")\n'
        '    lines.append("")\n'
        '    lines.append("***")\n'
        '    lines.append("")\n'
        '    lines.append("**Paradox** v" + provenance.get("tool_version", "?") +\n'
        '                 " · © 2026 Andrey Grigoryev (v314xm)")\n'
        '    lines.append("")\n'
    )
    return _patch(MARKDOWN, old, new, "markdown: author footer")


def patch_splash_animation():
    """Добавляем анимацию в прогресс-бар splash."""
    old = (
        '        # Заполнение\n'
        '        if self._progress > 0:\n'
        '            painter.setBrush(QColor("#5b8cff"))\n'
        '            fill_w = max(1, int(bar_w * self._progress))\n'
        '            painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 3, 3)\n'
    )
    new = (
        '        # Заполнение (с эффектом бегущего градиента)\n'
        '        if self._progress > 0:\n'
        '            fill_w = max(1, int(bar_w * self._progress))\n'
        '            grad = QLinearGradient(bar_x, 0, bar_x + fill_w, 0)\n'
        '            grad.setColorAt(0.0, QColor("#3a6ce0"))\n'
        '            grad.setColorAt(0.5, QColor("#5b8cff"))\n'
        '            grad.setColorAt(1.0, QColor("#8bb0ff"))\n'
        '            painter.setBrush(grad)\n'
        '            painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 3, 3)\n'
    )
    return _patch(SPLASH, old, new, "splash: gradient animation")


def main():
    print("=" * 60)
    print(" add branding features")
    print("=" * 60)
    ok = True
    try:
        patch_main_window()
    except Exception as e:
        print(f"[ERROR] main_window: {e}", file=sys.stderr)
        ok = False

    for fn in (patch_markdown, patch_splash_animation):
        try:
            if not fn(): ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False

    print("\nVerifying imports...")
    sys.path.insert(0, str(REPO_ROOT))
    import importlib
    for mod in ("paradox_gui.main_window", "paradox.reporters.markdown_reporter"):
        try:
            importlib.import_module(mod)
            print(f"[OK] {mod}")
        except Exception as e:
            print(f"[ERROR] {mod}: {e}", file=sys.stderr)
            ok = False

    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
