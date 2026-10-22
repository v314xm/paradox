"""Fix: add QFileDialog import to run_view.py (robust)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "views" / "run_view.py"


def main():
    print("=" * 60)
    print(" fix run_view: QFileDialog import")
    print("=" * 60)

    src = PATH.read_text(encoding="utf-8")

    # Уже есть? Тогда нечего делать
    if "QFileDialog" in src:
        print("[SKIP] QFileDialog already imported")
        return 0

    # Ищем любую строку импорта из PySide6.QtWidgets и вставляем QFileDialog
    markers = [
        "from PySide6.QtWidgets import (\n",
        "from PySide6.QtWidgets import QDialog, QScrollArea, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton, QVBoxLayout, QWidget\n",
    ]

    inserted = False
    for marker in markers:
        if marker in src:
            if marker.endswith("(\n"):
                # Блочный импорт
                new_marker = marker + "    QFileDialog,\n"
            else:
                # Строчный импорт — просто добавляем отдельную строку
                new_marker = "from PySide6.QtWidgets import QFileDialog\n" + marker
            src = src.replace(marker, new_marker, count=1)
            inserted = True
            print(f"[OK] added QFileDialog via marker: {marker[:40]}...")
            break

    if not inserted:
        # Fallback: добавляем сразу после первого импорта PySide6
        lines = src.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("from PySide6"):
                lines.insert(i, "from PySide6.QtWidgets import QFileDialog")
                src = "\n".join(lines)
                inserted = True
                print("[OK] added QFileDialog before first PySide6 import")
                break

    if not inserted:
        print("[ERROR] не нашёл ни один PySide6 import", file=sys.stderr)
        return 2

    PATH.write_text(src, encoding="utf-8")

    # Проверка импорта
    print("\nVerifying import...")
    import importlib
    try:
        import paradox_gui.views.run_view
        importlib.reload(paradox_gui.views.run_view)
        print("[OK] run_view.py imports")
    except Exception as e:
        print(f"[ERROR] import failed: {e}", file=sys.stderr)
        return 1

    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
