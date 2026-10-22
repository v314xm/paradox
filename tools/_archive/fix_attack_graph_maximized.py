"""Fix: Attack Graph maximized + fit after show."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "dialogs" / "attack_graph_dialog.py"


def _patch(path, old, new, name):
    src = path.read_text(encoding="utf-8")
    if new in src and old not in src:
        print(f"[SKIP] {name}: already applied")
        return True
    if old not in src:
        print(f"[ERROR] {name}: anchor not found", file=sys.stderr)
        return False
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


def fix_maximized():
    old = (
        '        self.setWindowTitle("Граф атаки")\n'
        '        self.setMinimumSize(1200, 800)\n'
        '        self._build()\n'
        '        self._draw()\n'
        '        if self._paths:\n'
        '            self._path_list.setCurrentRow(0)\n'
        '        from PySide6.QtCore import QTimer\n'
        '        QTimer.singleShot(100, self._view.fit)\n'
    )
    new = (
        '        self.setWindowTitle("Граф атаки")\n'
        '        self._build()\n'
        '        self._draw()\n'
        '        if self._paths:\n'
        '            self._path_list.setCurrentRow(0)\n'
        '        self.showMaximized()\n'
        '\n'
        '    def showEvent(self, event):\n'
        '        super().showEvent(event)\n'
        '        # Вызываем fit ТОЛЬКО когда окно уже развернуто на весь экран\n'
        '        self._view.fit()\n'
    )
    return _patch(PATH, old, new, "window maximized + fit on show")


def main():
    print("=" * 60)
    print(" fix attack_graph maximized")
    print("=" * 60)
    if fix_maximized():
        print("\nDONE")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
