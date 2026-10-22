"""Polish v2: arrows, thickness/style, node tooltip, double-click story."""
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


# ============================================================
# 1. Расширить _draw_edge: стрелки, толщина, стиль
# ============================================================
def patch_draw_edge():
    old = (
        '    def _draw_edge(self, src, dst, e):\n'
        '        x1, y1 = src\n'
        '        x2, y2 = dst\n'
        '        color = QColor(_PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a"))\n'
        '\n'
        '        path = QPainterPath()\n'
        '        path.moveTo(x1, y1)\n'
        '        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2 - 30\n'
        '        path.quadTo(cx, cy, x2, y2)\n'
        '\n'
        '        item = QGraphicsPathItem(path)\n'
        '        item.setPen(QPen(color, 2.0))\n'
        '        item.setData(2, color.name())\n'
        '        item.setToolTip(\n'
        '            f"{e[\'src\']} → {e[\'dst\']}\\n"\n'
        '            f"phase: {e.get(\'phase\')}\\n"\n'
        '            f"findings: {\', \'.join(e.get(\'finding_types\', []))}\\n"\n'
        '            f"severity: {e.get(\'severity\')}  conf: {e.get(\'confidence\', 0):.2f}"\n'
        '        )\n'
        '        self._scene.addItem(item)\n'
        '        self._edge_items.append(item)\n'
    )
    new = (
        '    def _draw_edge(self, src, dst, e):\n'
        '        import math\n'
        '        x1, y1 = src\n'
        '        x2, y2 = dst\n'
        '        color = QColor(_PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a"))\n'
        '\n'
        '        sev = e.get("severity", "info")\n'
        '        conf = float(e.get("confidence", 0.5))\n'
        '        # Толщина по severity, стиль по confidence\n'
        '        if sev in ("critical", "high"):\n'
        '            width = 3.0\n'
        '        elif sev == "medium":\n'
        '            width = 2.0\n'
        '        else:\n'
        '            width = 1.5\n'
        '        style = Qt.PenStyle.SolidLine if conf >= 0.5 else Qt.PenStyle.DashLine\n'
        '\n'
        '        path = QPainterPath()\n'
        '        path.moveTo(x1, y1)\n'
        '        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2 - 30\n'
        '        path.quadTo(cx, cy, x2, y2)\n'
        '\n'
        '        # Стрелка на конце\n'
        '        dx = x2 - cx\n'
        '        dy = y2 - cy\n'
        '        angle = math.atan2(dy, dx)\n'
        '        arrow_len = 10\n'
        '        arrow_angle = math.pi / 7\n'
        '        ax1 = x2 - arrow_len * math.cos(angle - arrow_angle)\n'
        '        ay1 = y2 - arrow_len * math.sin(angle - arrow_angle)\n'
        '        ax2 = x2 - arrow_len * math.cos(angle + arrow_angle)\n'
        '        ay2 = y2 - arrow_len * math.sin(angle + arrow_angle)\n'
        '        path.moveTo(x2, y2)\n'
        '        path.lineTo(ax1, ay1)\n'
        '        path.moveTo(x2, y2)\n'
        '        path.lineTo(ax2, ay2)\n'
        '\n'
        '        item = QGraphicsPathItem(path)\n'
        '        item.setPen(QPen(color, width, style))\n'
        '        item.setData(2, color.name())\n'
        '        item.setToolTip(\n'
        '            f"{e[\'src\']} → {e[\'dst\']}\\n"\n'
        '            f"phase: {e.get(\'phase\')}\\n"\n'
        '            f"findings: {\', \'.join(e.get(\'finding_types\', []))}\\n"\n'
        '            f"severity: {e.get(\'severity\')}  conf: {e.get(\'confidence\', 0):.2f}"\n'
        '        )\n'
        '        self._scene.addItem(item)\n'
        '        self._edge_items.append(item)\n'
    )
    return _patch(PATH, old, new, "_draw_edge: arrows + thickness + style")


# ============================================================
# 2. Tooltip + double-click на узлах
# ============================================================
def patch_draw_node():
    old = (
        '        item = QGraphicsEllipseItem(x - r, y - r, r * 2, r * 2)\n'
        '        item.setBrush(QBrush(color))\n'
        '        item.setPen(QPen(QColor("#ffffff"), 1.5))\n'
        '        self._scene.addItem(item)\n'
        '        self._node_items[n["ip"]] = item\n'
    )
    new = (
        '        item = QGraphicsEllipseItem(x - r, y - r, r * 2, r * 2)\n'
        '        item.setBrush(QBrush(color))\n'
        '        item.setPen(QPen(QColor("#ffffff"), 1.5))\n'
        '\n'
        '        # Tooltip с деталями узла\n'
        '        roles_str = ", ".join(n.get("roles", [])) or "—"\n'
        '        from datetime import datetime\n'
        '        def _fmt_ts(t):\n'
        '            if not t: return "—"\n'
        '            try:\n'
        '                return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")\n'
        '            except (OSError, ValueError):\n'
        '                return str(t)\n'
        '        tip_parts = [\n'
        '            f"<b>{n[\'ip\']}</b>",\n'
        '            f"{"Внутренний" if n.get("is_internal") else "Внешний"}",\n'
        '            f"Роль: {roles_str}",\n'
        '            f"Фаза: {n.get(\'phase_reached\', \'?\')}",\n'
        '            f"Findings: {n.get(\'findings_count\', 0)}",\n'
        '        ]\n'
        '        if n.get("is_pivot"): tip_parts.append("<b>⚠ PIVOT</b>")\n'
        '        if n.get("is_entry"): tip_parts.append("<b>ВХОД</b>")\n'
        '        if n.get("is_impact"): tip_parts.append("<b>ЦЕЛЬ АТАКИ</b>")\n'
        '        tip_parts.append(f"First seen: {_fmt_ts(n.get(\'first_ts\'))}")\n'
        '        tip_parts.append(f"Last seen: {_fmt_ts(n.get(\'last_ts\'))}")\n'
        '        item.setToolTip("<br>".join(tip_parts))\n'
        '\n'
        '        # Двойной клик → история хоста\n'
        '        ip_captured = n["ip"]\n'
        '        def _on_dbl_click(event, _ip=ip_captured):\n'
        '            self._open_host_story(_ip)\n'
        '        item.mouseDoubleClickEvent = _on_dbl_click\n'
        '        item.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable, True)\n'
        '\n'
        '        self._scene.addItem(item)\n'
        '        self._node_items[n["ip"]] = item\n'
    )
    return _patch(PATH, old, new, "_draw_node: tooltip + double-click")


# ============================================================
# 3. Метод _open_host_story
# ============================================================
def add_host_story_method():
    old = '    def _setup_timeline(self):\n'
    new = '''    def _open_host_story(self, ip: str):
        """Двойной клик на узле — история хоста."""
        try:
            from paradox.analyzers.story import build_host_story
            from paradox_gui.dialogs.host_story_dialog import HostStoryDialog
        except ImportError:
            return
        # Восстанавливаем отчёт из того, что есть в диалоге
        # (в графе только nodes/edges/paths — историю построить не из чего,
        # поэтому показываем просто findings этого узла)
        findings = []
        for e in self._edges:
            if ip in (e.get("src"), e.get("dst")):
                findings.append(e)
        if not findings:
            return
        html_parts = [f"<h3>{ip}</h3>", "<p><b>Связанные события:</b></p><ul>"]
        for e in findings:
            types = ", ".join(e.get("finding_types", []))
            direction = "→" if e.get("src") == ip else "←"
            other = e.get("dst") if e.get("src") == ip else e.get("src")
            html_parts.append(
                f"<li>{direction} <code>{other}</code>: {types} "
                f"({e.get('phase')}, {e.get('severity')})</li>"
            )
        html_parts.append("</ul>")
        try:
            from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton
            dlg = QDialog(self)
            dlg.setWindowTitle(f"Хост: {ip}")
            dlg.resize(600, 500)
            v = QVBoxLayout(dlg)
            tb = QTextBrowser()
            tb.setHtml("".join(html_parts))
            v.addWidget(tb)
            btn = QPushButton("Закрыть")
            btn.clicked.connect(dlg.accept)
            v.addWidget(btn)
            dlg.exec()
        except Exception:
            pass

    def _setup_timeline(self):
'''
    return _patch(PATH, old, new, "_open_host_story method")


def main():
    print("=" * 60)
    print(" polish attack graph v2")
    print("=" * 60)
    ok = True
    for fn in (patch_draw_edge, patch_draw_node, add_host_story_method):
        try:
            if not fn(): ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
