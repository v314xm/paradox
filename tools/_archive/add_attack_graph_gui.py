"""Attack Graph: dialog + button в RunView."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


DIALOG_PY = r'''"""Attack Graph dialog — визуализация цепочек атаки."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPen, QBrush, QFont, QPainter, QPainterPath
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QVBoxLayout, QWidget, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextBrowser,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsPathItem, QGraphicsTextItem, QSplitter,
)


_PHASE_COLOR = {
    "recon": "#5a7ab8", "initial_access": "#c060d0",
    "execution": "#e08040", "persistence": "#e08040",
    "lateral_movement": "#d05050", "c2": "#d0b040",
    "exfiltration": "#e060a0", "impact": "#ff5555",
    "other": "#5a5a6a",
}

_SEV_COLOR = {
    "critical": "#ff3030", "high": "#ff8040",
    "medium": "#d0c040", "low": "#50c050", "info": "#5a7ab8",
}


class _Zoomable(QGraphicsView):
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self._scene = scene
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QColor("#1e1e24"))

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)

    def fit(self):
        rect = self._scene.itemsBoundingRect()
        if not rect.isNull() and rect.width() > 0 and rect.height() > 0:
            self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)


class AttackGraphDialog(QDialog):
    def __init__(self, report: dict, parent=None) -> None:
        super().__init__(parent)
        self._graph = (report or {}).get("attack_graph", {}) or {}
        self._nodes = self._graph.get("nodes", [])
        self._edges = self._graph.get("edges", [])
        self._paths = self._graph.get("paths", [])
        self._impacts = set(self._graph.get("impact_targets", []))
        self._node_items: dict[str, QGraphicsEllipseItem] = {}
        self._edge_items: list[QGraphicsPathItem] = []
        self.setWindowTitle("Граф атаки")
        self.resize(1400, 900)
        self._build()
        self._draw()
        if self._paths:
            self._path_list.setCurrentRow(0)

    def _build(self):
        root = QHBoxLayout(self)

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(8, 8, 8, 8)
        lbl = QLabel(f"Пути атаки ({len(self._paths)})")
        lbl.setStyleSheet("font-weight: 600; font-size: 14px;")
        lv.addWidget(lbl)
        self._path_list = QListWidget()
        self._path_list.setMinimumWidth(320)
        for i, p in enumerate(self._paths):
            item = QListWidgetItem(self._fmt_path(p))
            item.setData(Qt.ItemDataRole.UserRole, i)
            col = _SEV_COLOR.get(p.get("severity", "medium"), "#d0c040")
            item.setForeground(QBrush(QColor(col)))
            self._path_list.addItem(item)
        self._path_list.currentRowChanged.connect(self._on_select)
        lv.addWidget(self._path_list, stretch=1)
        left.setFixedWidth(360)

        self._scene = QGraphicsScene(self)
        self._view = _Zoomable(self._scene)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(8, 8, 8, 8)
        r_lbl = QLabel("Детали пути")
        r_lbl.setStyleSheet("font-weight: 600; font-size: 14px;")
        rv.addWidget(r_lbl)
        self._details = QTextBrowser()
        rv.addWidget(self._details, stretch=1)
        right.setFixedWidth(360)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(self._view)
        splitter.addWidget(right)
        splitter.setSizes([340, 700, 340])
        root.addWidget(splitter)

        btn = QPushButton("Закрыть")
        btn.setObjectName("primary")
        btn.clicked.connect(self.accept)
        root.addWidget(btn, alignment=Qt.AlignmentFlag.AlignBottom)

    def _fmt_path(self, p: dict) -> str:
        sev = p.get("severity", "medium")
        conf = p.get("confidence", 0)
        nodes = p.get("nodes", [])
        short = " → ".join(nodes[:4])
        if len(nodes) > 4:
            short += f" → … ({len(nodes)} hops)"
        return f"[{sev} {conf:.2f}] {short}"

    def _draw(self):
        if not self._nodes:
            text = QGraphicsTextItem("Нет данных об атаке — findings не образовали связей.")
            text.setDefaultTextColor(QColor("#a0a0b0"))
            self._scene.addItem(text)
            return

        groups: dict[int, list[dict]] = {}
        for n in self._nodes:
            groups.setdefault(n.get("phase_order", 999), []).append(n)

        pos: dict[str, tuple[float, float]] = {}
        for order in sorted(groups.keys()):
            bucket = groups[order]
            x = (order // 10) * 260
            for i, n in enumerate(bucket):
                y = (i - (len(bucket) - 1) / 2) * 120
                pos[n["ip"]] = (x, y)

        for e in self._edges:
            if e["src"] in pos and e["dst"] in pos:
                self._draw_edge(pos[e["src"]], pos[e["dst"]], e)

        for n in self._nodes:
            if n["ip"] in pos:
                self._draw_node(pos[n["ip"]], n)

        self._view.fit()

    def _draw_node(self, p, n):
        x, y = p
        r = 22.0
        if n.get("is_pivot") or n.get("is_impact"):
            r = 30.0
        if n.get("is_entry"):
            r = 28.0

        color = QColor(_PHASE_COLOR.get(n.get("phase_reached", "other"), "#5a5a6a"))
        if n.get("is_entry"):
            color = QColor("#40c040")
        elif n.get("is_impact"):
            color = QColor("#e04040")
        elif n.get("is_pivot"):
            color = QColor("#e0a040")

        item = QGraphicsEllipseItem(x - r, y - r, r * 2, r * 2)
        item.setBrush(QBrush(color))
        item.setPen(QPen(QColor("#ffffff"), 1.5))
        self._scene.addItem(item)
        self._node_items[n["ip"]] = item

        lbl = QGraphicsTextItem(n["ip"])
        lbl.setDefaultTextColor(QColor("#ffffff"))
        lbl.setFont(QFont("Consolas", 8))
        lbl.setPos(x - lbl.boundingRect().width() / 2, y + r + 4)
        self._scene.addItem(lbl)

        if n.get("is_pivot"):
            tag = QGraphicsTextItem("PIVOT")
            tag.setDefaultTextColor(QColor("#ffffff"))
            tag.setFont(QFont("Consolas", 7, QFont.Weight.Bold))
            tag.setPos(x - 20, y - r - 16)
            self._scene.addItem(tag)

    def _draw_edge(self, src, dst, e):
        x1, y1 = src
        x2, y2 = dst
        color = QColor(_PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a"))

        path = QPainterPath()
        path.moveTo(x1, y1)
        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2 - 30
        path.quadTo(cx, cy, x2, y2)

        item = QGraphicsPathItem(path)
        item.setPen(QPen(color, 2.0))
        item.setData(2, color.name())
        item.setToolTip(
            f"{e['src']} → {e['dst']}\n"
            f"phase: {e.get('phase')}\n"
            f"findings: {', '.join(e.get('finding_types', []))}\n"
            f"severity: {e.get('severity')}  conf: {e.get('confidence', 0):.2f}"
        )
        self._scene.addItem(item)
        self._edge_items.append(item)

    def _on_select(self, row: int):
        if row < 0 or row >= len(self._paths):
            return
        path = self._paths[row]
        nodes_in = set(path.get("nodes", []))
        edges_in = {(e["src"], e["dst"]) for e in path.get("edges", [])}

        for ip, item in self._node_items.items():
            item.setOpacity(1.0 if ip in nodes_in else 0.15)
        for item in self._edge_items:
            src, dst = item.data(0), item.data(1)
            if (src, dst) in edges_in:
                item.setOpacity(1.0)
            else:
                item.setOpacity(0.15)

        html = f"<h3>Путь {row + 1}</h3>"
        html += f"<p><b>Severity:</b> {path.get('severity')}</p>"
        html += f"<p><b>Confidence:</b> {path.get('confidence', 0):.2f}</p>"
        html += f"<p><b>Score:</b> {path.get('score', 0):.2f}</p>"
        html += f"<p><b>Hop count:</b> {len(path.get('edges', []))}</p>"
        html += "<h4>Фазы:</h4><ol>"
        for ph in path.get("phases", []):
            html += f"<li><code>{ph}</code></li>"
        html += "</ol>"
        mitre = path.get("mitre", [])
        if mitre:
            html += "<h4>MITRE ATT&CK:</h4><ul>"
            for t in mitre:
                html += f"<li><code>{t}</code></li>"
            html += "</ul>"
        html += "<h4>Рёбра:</h4><ul>"
        for edge in path.get("edges", []):
            html += (
                f"<li><code>{edge['src']} → {edge['dst']}</code><br>"
                f"<small>{', '.join(edge.get('finding_types', []))} "
                f"({edge.get('phase')})</small></li>"
            )
        html += "</ul>"
        self._details.setHtml(html)
'''


def add_dialog() -> bool:
    target = REPO_ROOT / "paradox_gui" / "dialogs" / "attack_graph_dialog.py"
    if target.exists():
        print(f"[SKIP] {target.relative_to(REPO_ROOT)} exists")
        return True
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DIALOG_PY, encoding="utf-8")
    print(f"[OK] created {target.relative_to(REPO_ROOT)}")
    return True


def add_button_to_run_view() -> bool:
    path = REPO_ROOT / "paradox_gui" / "views" / "run_view.py"
    src = path.read_text(encoding="utf-8")
    if "btn_attack_graph" in src:
        print("[SKIP] run_view: button already added")
        return True

    old = (
        '        self.btn_graph.clicked.connect(self._on_graph_clicked)\n'
        '        findings_header.addWidget(self.btn_graph)\n'
    )
    new = old + (
        '\n'
        '        self.btn_attack_graph = QPushButton("Граф атаки")\n'
        '        self.btn_attack_graph.setEnabled(False)\n'
        '        self.btn_attack_graph.clicked.connect(self._on_attack_graph_clicked)\n'
        '        findings_header.addWidget(self.btn_attack_graph)\n'
    )
    if old not in src:
        print("[ERROR] run_view: button anchor not found", file=sys.stderr)
        return False
    src = src.replace(old, new, count=1)

    # Enable in _on_ok and load_report
    old_enable = (
        "        self.btn_graph.setEnabled(True)\n"
        "        self.btn_carved.setEnabled(bool((report.get('carved_files') or {}).get('total')))\n"
    )
    new_enable = (
        "        self.btn_graph.setEnabled(True)\n"
        "        _ag = report.get('attack_graph') or {}\n"
        "        self.btn_attack_graph.setEnabled(bool(_ag.get('paths')))\n"
        "        self.btn_carved.setEnabled(bool((report.get('carved_files') or {}).get('total')))\n"
    )
    if old_enable not in src:
        print("[ERROR] run_view: enable anchor not found", file=sys.stderr)
        return False
    src = src.replace(old_enable, new_enable, count=2)

    # Disable in _reset_results
    old_reset = (
        "        if hasattr(self, \"btn_what_if\"):\n"
        "            self.btn_what_if.setEnabled(False)\n"
        "            self.btn_graph.setEnabled(False)\n"
        "            self.btn_reset_filter.setVisible(False)\n"
    )
    new_reset = (
        "        if hasattr(self, \"btn_what_if\"):\n"
        "            self.btn_what_if.setEnabled(False)\n"
        "            self.btn_graph.setEnabled(False)\n"
        "            self.btn_attack_graph.setEnabled(False)\n"
        "            self.btn_reset_filter.setVisible(False)\n"
    )
    if old_reset not in src:
        print("[ERROR] run_view: reset anchor not found", file=sys.stderr)
        return False
    src = src.replace(old_reset, new_reset, count=1)

    # Handler after _on_graph_clicked
    old_handler = (
        "    def _on_graph_clicked(self) -> None:\n"
        "        if not self._last_report:\n"
        "            return\n"
        "        GraphDialog(self._last_report, self).exec()\n"
    )
    new_handler = old_handler + (
        "\n"
        "    def _on_attack_graph_clicked(self) -> None:\n"
        "        if not self._last_report:\n"
        "            return\n"
        "        from paradox_gui.dialogs.attack_graph_dialog import AttackGraphDialog\n"
        "        AttackGraphDialog(self._last_report, self).exec()\n"
    )
    if old_handler not in src:
        print("[ERROR] run_view: handler anchor not found", file=sys.stderr)
        return False
    src = src.replace(old_handler, new_handler, count=1)

    path.write_text(src, encoding="utf-8")
    print("[OK] run_view: button + handler added")
    return True


def main() -> int:
    print("=" * 60)
    print(" attack graph: gui")
    print("=" * 60)
    ok = True
    for fn in (add_dialog, add_button_to_run_view):
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
