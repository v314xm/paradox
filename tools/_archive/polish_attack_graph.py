"""Polish: add legend and hints to attack graph."""
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


def add_legend():
    old = (
        '        # --- Центральная панель: граф + таймлайн ---\n'
        '        self._scene = QGraphicsScene(self)\n'
        '        self._view = _Zoomable(self._scene)\n'
        '\n'
        '        center_widget = QWidget()\n'
        '        center_layout = QVBoxLayout(center_widget)\n'
        '        center_layout.setContentsMargins(0, 0, 0, 0)\n'
        '        center_layout.addWidget(self._view, stretch=1)\n'
    )
    new = (
        '        # --- Центральная панель: легенда + граф + таймлайн ---\n'
        '        self._scene = QGraphicsScene(self)\n'
        '        self._view = _Zoomable(self._scene)\n'
        '\n'
        '        center_widget = QWidget()\n'
        '        center_layout = QVBoxLayout(center_widget)\n'
        '        center_layout.setContentsMargins(0, 0, 0, 0)\n'
        '\n'
        '        # Легенда\n'
        '        legend_layout = QHBoxLayout()\n'
        '        legend_layout.setContentsMargins(8, 4, 8, 4)\n'
        '        legend_layout.setSpacing(16)\n'
        '        legend_layout.addWidget(QLabel("<b>Легенда:</b>"))\n'
        '\n'
        '        def _lbl(color, text):\n'
        '            return QLabel(f"<span style=\'color:{color}; font-size:18px;\'>●</span> {text}")\n'
        '\n'
        '        legend_layout.addWidget(_lbl("#40c040", "Вход / Жертва"))\n'
        '        legend_layout.addWidget(_lbl("#e0a040", "Pivot (Скомпрометирован)"))\n'
        '        legend_layout.addWidget(_lbl("#e04040", "Impact / C2 (Цель)"))\n'
        '        legend_layout.addSpacing(24)\n'
        '        legend_layout.addWidget(QLabel("<span style=\'color:#a0a0b0;\'>Линии: цвет = фаза kill-chain</span>"))\n'
        '        legend_layout.addStretch(1)\n'
        '        legend_layout.addWidget(QLabel("<i style=\'color:#808090; font-size:11px;\'>Колесико мыши — масштаб | Зажать ЛКМ — перемещение</i>"))\n'
        '\n'
        '        center_layout.addLayout(legend_layout)\n'
        '        center_layout.addWidget(self._view, stretch=1)\n'
    )
    return _patch(PATH, old, new, "legend + hints")


def main():
    print("=" * 60)
    print(" polish attack graph: legend")
    print("=" * 60)
    ok = add_legend()
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
