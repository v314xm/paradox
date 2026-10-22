"""Fix: Attack Graph maximized + dynamic layout."""
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


def fix_window_size():
    old = (
        '        self.setWindowTitle("Граф атаки")\n'
        '        self.resize(1400, 900)\n'
        '        self._build()\n'
        '        self._draw()\n'
        '        if self._paths:\n'
        '            self._path_list.setCurrentRow(0)\n'
    )
    new = (
        '        self.setWindowTitle("Граф атаки")\n'
        '        self.setMinimumSize(1200, 800)\n'
        '        self._build()\n'
        '        self._draw()\n'
        '        if self._paths:\n'
        '            self._path_list.setCurrentRow(0)\n'
        '        from PySide6.QtCore import QTimer\n'
        '        QTimer.singleShot(100, self._view.fit)\n'
    )
    return _patch(PATH, old, new, "window size")


def fix_layout_coords():
    # Динамические координаты по X вместо магических order // 10 * 260
    old = (
        '        pos: dict[str, tuple[float, float]] = {}\n'
        '        for order in sorted(groups.keys()):\n'
        '            bucket = groups[order]\n'
        '            x = (order // 10) * 260\n'
        '            for i, n in enumerate(bucket):\n'
        '                y = (i - (len(bucket) - 1) / 2) * 120\n'
        '                pos[n["ip"]] = (x, y)\n'
    )
    new = (
        '        pos: dict[str, tuple[float, float]] = {}\n'
        '        sorted_phases = sorted(groups.keys())\n'
        '        phase_to_x = {ph: idx * 320 for idx, ph in enumerate(sorted_phases)}\n'
        '\n'
        '        for order in sorted_phases:\n'
        '            bucket = groups[order]\n'
        '            x = phase_to_x[order]\n'
        '            for i, n in enumerate(bucket):\n'
        '                # Больше отступ по Y, чтобы узлы не слипались\n'
        '                y = (i - (len(bucket) - 1) / 2) * 160\n'
        '                pos[n["ip"]] = (x, y)\n'
    )
    return _patch(PATH, old, new, "layout coordinates")


def main():
    print("=" * 60)
    print(" fix attack_graph zoom & layout")
    print("=" * 60)
    ok = True
    for fn in (fix_window_size, fix_layout_coords):
        try:
            if not fn():
                ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
