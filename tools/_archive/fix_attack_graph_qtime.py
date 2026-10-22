"""Fix: import QTimer in attack_graph_dialog."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "dialogs" / "attack_graph_dialog.py"

def main():
    src = PATH.read_text(encoding="utf-8")
    old = "from PySide6.QtCore import Qt"
    new = "from PySide6.QtCore import Qt, QTimer"

    if new in src:
        print("[SKIP] QTimer already imported")
        return 0

    if old not in src:
        print("[ERROR] import anchor not found", file=sys.stderr)
        return 1

    PATH.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print("[OK] QTimer imported")
    return 0

if __name__ == "__main__":
    sys.exit(main())
