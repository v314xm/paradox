"""Fix: QTreeWidget в тёмной теме (белые строки в Diff/Timeline)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
THEME_PY = REPO_ROOT / "paradox_gui" / "theme.py"

OLD = '''QTableWidget, QTableView {{
    background-color: {bg_light};
    border: 1px solid {border};
    gridline-color: {border};
    selection-background-color: {bg_hover};
    alternate-background-color: {bg};
}}'''

NEW = '''QTableWidget, QTableView, QTreeWidget, QTreeView {{
    background-color: {bg_light};
    border: 1px solid {border};
    gridline-color: {border};
    selection-background-color: {bg_hover};
    alternate-background-color: {bg};
}}
QTreeWidget::item, QTreeView::item {{
    padding: 4px 6px;
    color: {text};
}}
QTreeWidget::item:selected, QTreeView::item:selected {{
    background: {bg_hover};
    color: {text};
}}
QTreeView::branch {{
    background: transparent;
}}'''


def main() -> int:
    if not THEME_PY.exists():
        print(f"ERROR: {THEME_PY} not found", file=sys.stderr)
        return 1
    src = THEME_PY.read_text(encoding="utf-8")
    if "QTreeWidget, QTreeView" in src:
        print("[SKIP] already applied")
        return 0
    if OLD not in src:
        print("ERROR: anchor not found in theme.py", file=sys.stderr)
        return 2
    THEME_PY.write_text(src.replace(OLD, NEW, count=1), encoding="utf-8")
    print("[OK] QTreeWidget styled in theme.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
