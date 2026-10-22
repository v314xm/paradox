"""Fix: insert export buttons into existing btn_row in attack_graph_dialog."""
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


def add_buttons():
    # Ищем стандартное создание btn_row и добавляем кнопки экспорта перед stretch
    old = (
        '        btn_row = QHBoxLayout()\n'
        '        btn_row.addStretch(1)\n'
    )
    new = (
        '        btn_row = QHBoxLayout()\n'
        '        btn_row.addWidget(QLabel("<b>Экспорт:</b>"))\n'
        '        btn_png = QPushButton("PNG")\n'
        '        btn_png.clicked.connect(self._export_png)\n'
        '        btn_row.addWidget(btn_png)\n'
        '        btn_dot = QPushButton("DOT")\n'
        '        btn_dot.clicked.connect(self._export_dot)\n'
        '        btn_row.addWidget(btn_dot)\n'
        '        btn_gml = QPushButton("GraphML")\n'
        '        btn_gml.clicked.connect(self._export_graphml)\n'
        '        btn_row.addWidget(btn_gml)\n'
        '        btn_row.addStretch(1)\n'
    )
    return _patch(PATH, old, new, "export buttons")


def main():
    print("=" * 60)
    print(" fix attack_graph export buttons")
    print("=" * 60)
    if add_buttons():
        print("\nDONE")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
