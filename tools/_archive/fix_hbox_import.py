"""Fix: ensure QHBoxLayout imported in main_window.py."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "main_window.py"


def main():
    src = PATH.read_text(encoding="utf-8")

    if "    QHBoxLayout,\n" in src or "from PySide6.QtWidgets import QHBoxLayout" in src:
        print("[SKIP] QHBoxLayout already imported")
        return 0

    # Ищем блок "from PySide6.QtWidgets import ("
    marker = "from PySide6.QtWidgets import (\n"
    if marker in src:
        idx = src.find(marker) + len(marker)
        src = src[:idx] + "    QHBoxLayout,\n" + src[idx:]
        PATH.write_text(src, encoding="utf-8")
        print("[OK] QHBoxLayout добавлен в блок импортов")
        return 0

    # Fallback: отдельной строкой
    marker2 = "from PySide6.QtWidgets import"
    if marker2 in src:
        idx = src.find(marker2)
        src = src[:idx] + "from PySide6.QtWidgets import QHBoxLayout\n" + src[idx:]
        PATH.write_text(src, encoding="utf-8")
        print("[OK] QHBoxLayout добавлен отдельной строкой")
        return 0

    print("[ERROR] не нашёл ни один PySide6.QtWidgets import", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
