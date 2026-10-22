"""Fix: visible arrows on attack graph edges (border-trimmed + setData)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox_gui" / "dialogs" / "attack_graph_dialog.py"


NEW_DRAW_EDGE = '''    def _draw_edge(self, src, dst, e, src_r: float = 22.0, dst_r: float = 22.0):
        import math
        x1, y1 = src
        x2, y2 = dst
        color = QColor(_PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a"))

        sev = e.get("severity", "info")
        conf = float(e.get("confidence", 0.5))
        if sev in ("critical", "high"):
            width = 3.0
        elif sev == "medium":
            width = 2.0
        else:
            width = 1.5
        style = Qt.PenStyle.SolidLine if conf >= 0.5 else Qt.PenStyle.DashLine

        # Обрезка линии по границам кругов-узлов (v1.2.1)
        dx_total = x2 - x1
        dy_total = y2 - y1
        dist = math.sqrt(dx_total * dx_total + dy_total * dy_total)
        if dist > 0:
            ux, uy = dx_total / dist, dy_total / dist
        else:
            ux, uy = 1.0, 0.0

        src_trim = src_r + 4
        dst_trim = dst_r + 4
        if dist < src_trim + dst_trim + 8:
            src_trim = min(src_trim, dist / 2 - 4)
            dst_trim = min(dst_trim, dist / 2 - 4)

        start_x = x1 + ux * src_trim
        start_y = y1 + uy * src_trim
        end_x = x2 - ux * dst_trim
        end_y = y2 - uy * dst_trim

        # Кривая
        path = QPainterPath()
        path.moveTo(start_x, start_y)
        cx, cy = (start_x + end_x) / 2, (start_y + end_y) / 2 - 30
        path.quadTo(cx, cy, end_x, end_y)

        # Стрелка по касательной (от control point к end)
        tan_dx = end_x - cx
        tan_dy = end_y - cy
        angle = math.atan2(tan_dy, tan_dx)
        arrow_len = 14
        arrow_angle = math.pi / 7
        ax1 = end_x - arrow_len * math.cos(angle - arrow_angle)
        ay1 = end_y - arrow_len * math.sin(angle - arrow_angle)
        ax2 = end_x - arrow_len * math.cos(angle + arrow_angle)
        ay2 = end_y - arrow_len * math.sin(angle + arrow_angle)
        path.moveTo(end_x, end_y)
        path.lineTo(ax1, ay1)
        path.moveTo(end_x, end_y)
        path.lineTo(ax2, ay2)

        item = QGraphicsPathItem(path)
        item.setPen(QPen(color, width, style))
        item.setData(0, e["src"])       # для подсветки (v1.2.1: фикс)
        item.setData(1, e["dst"])       # для подсветки (v1.2.1: фикс)
        item.setData(2, color.name())
        item.setToolTip(
            f"{e['src']} \u2192 {e['dst']}\\n"
            f"phase: {e.get('phase')}\\n"
            f"findings: {', '.join(e.get('finding_types', []))}\\n"
            f"severity: {e.get('severity')}  conf: {e.get('confidence', 0):.2f}"
        )
        self._scene.addItem(item)
        self._edge_items.append(item)
'''


def replace_draw_edge():
    src = PATH.read_text(encoding="utf-8")

    start = src.find("    def _draw_edge(self, src, dst, e):")
    if start < 0:
        print("[ERROR] _draw_edge not found", file=sys.stderr)
        return False
    end = src.find("\n    def ", start + 10)
    if end < 0:
        end = len(src)

    src = src[:start] + NEW_DRAW_EDGE + src[end:]
    PATH.write_text(src, encoding="utf-8")
    print("[OK] _draw_edge rewritten (border trim + setData)")
    return True


def patch_draw_graph_loop():
    src = PATH.read_text(encoding="utf-8")

    old = (
        '        for e in self._edges:\n'
        '            if e["src"] in pos and e["dst"] in pos:\n'
        '                self._draw_edge(pos[e["src"]], pos[e["dst"]], e)\n'
    )
    new = (
        '        # v1.2.1: радиусы для обрезки стрелок\n'
        '        nodes_by_ip = {n["ip"]: n for n in self._nodes}\n'
        '        def _node_r(n):\n'
        '            if not n:\n'
        '                return 22.0\n'
        '            r = 22.0\n'
        '            if n.get("is_pivot") or n.get("is_impact"):\n'
        '                r = 30.0\n'
        '            if n.get("is_entry"):\n'
        '                r = 28.0\n'
        '            return r\n'
        '\n'
        '        for e in self._edges:\n'
        '            if e["src"] in pos and e["dst"] in pos:\n'
        '                _sr = _node_r(nodes_by_ip.get(e["src"]))\n'
        '                _dr = _node_r(nodes_by_ip.get(e["dst"]))\n'
        '                self._draw_edge(pos[e["src"]], pos[e["dst"]], e, _sr, _dr)\n'
    )
    if old not in src:
        print("[ERROR] _draw_graph loop not found", file=sys.stderr)
        return False
    PATH.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print("[OK] _draw_graph passes radii")
    return True


def patch_dim_opacity():
    src = PATH.read_text(encoding="utf-8")
    old = (
        '        for item in self._edge_items:\n'
        '            src, dst = item.data(0), item.data(1)\n'
        '            if (src, dst) in edges_in:\n'
        '                item.setOpacity(1.0)\n'
        '            else:\n'
        '                item.setOpacity(0.15)\n'
    )
    new = (
        '        for item in self._edge_items:\n'
        '            _src, _dst = item.data(0), item.data(1)\n'
        '            if (_src, _dst) in edges_in:\n'
        '                item.setOpacity(1.0)\n'
        '            else:\n'
        '                item.setOpacity(0.25)\n'
    )
    if old in src:
        PATH.write_text(src.replace(old, new, count=1), encoding="utf-8")
        print("[OK] dim opacity: 0.15 → 0.25 (видимее)")
        return True
    if "item.setOpacity(0.25)" in src:
        print("[SKIP] dim opacity already 0.25")
        return True
    print("[WARN] dim opacity anchor not found")
    return True


def main():
    print("=" * 60)
    print(" fix attack graph arrows")
    print("=" * 60)
    ok = True
    for fn in (replace_draw_edge, patch_draw_graph_loop, patch_dim_opacity):
        try:
            if not fn(): ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False

    print("\nVerifying...")
    sys.path.insert(0, str(REPO_ROOT))
    try:
        import importlib

        import paradox_gui.dialogs.attack_graph_dialog
        importlib.reload(paradox_gui.dialogs.attack_graph_dialog)
        print("[OK] attack_graph_dialog imports")
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        ok = False

    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
