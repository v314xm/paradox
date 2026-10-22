"""Feat: Attack Graph export to PNG, DOT, GraphML."""
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


def add_imports():
    old = (
        '    QGraphicsPathItem, QGraphicsTextItem, QSplitter,\n'
        '    QSlider,\n'
        ')\n'
    )
    new = (
        '    QGraphicsPathItem, QGraphicsTextItem, QSplitter,\n'
        '    QSlider, QFileDialog, QMessageBox,\n'
        ')\n'
        'from PySide6.QtGui import QImage, QPainter\n'
    )
    return _patch(PATH, old, new, "imports")


def add_buttons():
    old = (
        '        btn_row = QHBoxLayout()\n'
        '        btn_row.addStretch(1)\n'
        '        btn = QPushButton("Закрыть")\n'
        '        btn.setObjectName("primary")\n'
        '        btn.clicked.connect(self.accept)\n'
        '        btn_row.addWidget(btn)\n'
        '        root.addLayout(btn_row)\n'
    )
    new = (
        '        btn_row = QHBoxLayout()\n'
        '        btn_row.addWidget(QLabel("<b>Экспорт:</b>"))\n'
        '        \n'
        '        btn_png = QPushButton("PNG")\n'
        '        btn_png.clicked.connect(self._export_png)\n'
        '        btn_row.addWidget(btn_png)\n'
        '        \n'
        '        btn_dot = QPushButton("DOT (Graphviz)")\n'
        '        btn_dot.clicked.connect(self._export_dot)\n'
        '        btn_row.addWidget(btn_dot)\n'
        '        \n'
        '        btn_gml = QPushButton("GraphML (Gephi/Neo4j)")\n'
        '        btn_gml.clicked.connect(self._export_graphml)\n'
        '        btn_row.addWidget(btn_gml)\n'
        '\n'
        '        btn_row.addStretch(1)\n'
        '        btn = QPushButton("Закрыть")\n'
        '        btn.setObjectName("primary")\n'
        '        btn.clicked.connect(self.accept)\n'
        '        btn_row.addWidget(btn)\n'
        '        root.addLayout(btn_row)\n'
    )
    return _patch(PATH, old, new, "export buttons")


def add_export_methods():
    old = '    def _on_select(self, row: int):\n'
    new = '''    def _export_png(self):
        if not self._nodes:
            QMessageBox.warning(self, "Экспорт PNG", "Граф пуст — нечего сохранять.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить граф как PNG", "attack_graph.png", "PNG (*.png)"
        )
        if not path:
            return
        try:
            rect = self._scene.itemsBoundingRect()
            if rect.isNull():
                return
            # Отступ 20px со всех сторон
            rect.adjust(-20, -20, 20, 20)
            image = QImage(rect.size().toSize(), QImage.Format.Format_ARGB32)
            image.fill(QColor("#1e1e2e")) # цвет фона как в теме
            painter = QPainter(image)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            self._scene.render(painter, target=image.rect(), source=rect)
            painter.end()
            image.save(path, "PNG")
            QMessageBox.information(self, "Экспорт PNG", f"Успешно сохранено:\\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта PNG", str(e))

    def _export_dot(self):
        if not self._nodes:
            QMessageBox.warning(self, "Экспорт DOT", "Граф пуст.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить граф как DOT", "attack_graph.dot", "DOT (*.dot)"
        )
        if not path:
            return
        try:
            lines = ["digraph AttackGraph {", "  rankdir=LR;", "  node [shape=circle, style=filled];"]
            for n in self._nodes:
                color = "#40c040" if n.get("is_entry") else ("#e04040" if n.get("is_impact") else ("#e0a040" if n.get("is_pivot") else "#5a5a6a"))
                label = n["ip"]
                if n.get("is_pivot"): label += "\\n(PIVOT)"
                lines.append(f'  "{n["ip"]}" [fillcolor="{color}", label="{label}"];')

            for e in self._edges:
                color = _PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a")
                label = ", ".join(e.get("finding_types", []))
                lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{label}", color="{color}"];')
            lines.append("}")
            Path(path).write_text("\\n".join(lines), encoding="utf-8")
            QMessageBox.information(self, "Экспорт DOT", f"Успешно сохранено:\\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта DOT", str(e))

    def _export_graphml(self):
        if not self._nodes:
            QMessageBox.warning(self, "Экспорт GraphML", "Граф пуст.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить граф как GraphML", "attack_graph.graphml", "GraphML (*.graphml)"
        )
        if not path:
            return
        try:
            import xml.etree.ElementTree as ET
            root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")

            key_label = ET.SubElement(root, "key", id="label", **{"for": "all", "attr.name": "label", "attr.type": "string"})
            key_sev = ET.SubElement(root, "key", id="severity", **{"for": "edge", "attr.name": "severity", "attr.type": "string"})

            graph = ET.SubElement(root, "graph", id="G", edgedefault="directed")

            for n in self._nodes:
                node_el = ET.SubElement(graph, "node", id=n["ip"])
                data_el = ET.SubElement(node_el, "data", key="label")
                data_el.text = n["ip"]

            for i, e in enumerate(self._edges):
                edge_el = ET.SubElement(graph, "edge", id=f"e{i}", source=e["src"], target=e["dst"])
                label = ", ".join(e.get("finding_types", []))
                ET.SubElement(edge_el, "data", key="label").text = label
                ET.SubElement(edge_el, "data", key="severity").text = e.get("severity", "info")

            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ")
            tree.write(path, encoding="utf-8", xml_declaration=True)
            QMessageBox.information(self, "Экспорт GraphML", f"Успешно сохранено:\\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта GraphML", str(e))

    def _on_select(self, row: int):
'''
    return _patch(PATH, old, new, "export methods")


def main():
    print("=" * 60)
    print(" attack_graph: export PNG/DOT/GraphML")
    print("=" * 60)
    ok = True
    for fn in (add_imports, add_buttons, add_export_methods):
        try:
            if not fn(): ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
