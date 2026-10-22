"""Генерация paradox.ico из существующего render_logo().

Использование:
    python tools/build_icon.py

Создаёт paradox.ico в корне проекта. Файл коммитится в репозиторий.
"""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("error: PySide6 not installed")
        return 1

    app = QApplication.instance() or QApplication(sys.argv)  # noqa: F841

    from paradox_gui.logo import render_logo

    pm = render_logo(256)
    if pm.isNull():
        print("error: render_logo() returned null pixmap")
        return 1

    out = project_root / "paradox.ico"
    if not pm.save(str(out), "ICO"):
        print(f"error: failed to save {out}")
        return 1

    size_kb = out.stat().st_size / 1024
    print(f"wrote {out} ({size_kb:.1f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
