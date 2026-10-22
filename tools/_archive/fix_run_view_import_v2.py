"""Fix v2: add QFileDialog import (real import check)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "views" / "run_view.py"


def main():
    print("=" * 60)
    print(" fix run_view: QFileDialog (real check)")
    print("=" * 60)

    # Реальная проверка: экспортируется ли QFileDialog из модуля
    sys.path.insert(0, str(REPO_ROOT))
    try:
        import paradox_gui.views.run_view as rv
        if hasattr(rv, "QFileDialog"):
            print("[SKIP] QFileDialog действительно импортирован")
            return 0
        print("[INFO] QFileDialog не импортирован (только используется)")
    except ImportError as e:
        print(f"[WARN] не удалось загрузить модуль: {e}")

    # Нужно вставить импорт
    src = PATH.read_text(encoding="utf-8")

    # Ищем блок "from PySide6.QtWidgets import ("
    block_marker = "from PySide6.QtWidgets import (\n"
    if block_marker in src:
        # Найдём первую строку внутри скобок и вставим QFileDialog
        idx = src.find(block_marker) + len(block_marker)
        # Вставляем как первый элемент
        new_src = src[:idx] + "    QFileDialog,\n" + src[idx:]
        PATH.write_text(new_src, encoding="utf-8")
        print("[OK] добавлено в начало блока from PySide6.QtWidgets import (")
    else:
        # Строчный вариант — добавляем отдельной строкой перед первым PySide6 import
        lines = src.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("from PySide6"):
                lines.insert(i, "from PySide6.QtWidgets import QFileDialog")
                PATH.write_text("\n".join(lines), encoding="utf-8")
                print("[OK] добавлено отдельной строкой")
                break
        else:
            print("[ERROR] не нашёл ни один PySide6 import", file=sys.stderr)
            return 2

    # Проверка
    print("\nVerifying import...")
    import importlib
    try:
        import paradox_gui.views.run_view
        importlib.reload(paradox_gui.views.run_view)
        if hasattr(paradox_gui.views.run_view, "QFileDialog"):
            print("[OK] QFileDialog теперь импортирован")
        else:
            print("[ERROR] импорт не сработал", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"[ERROR] import failed: {e}", file=sys.stderr)
        return 1

    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
