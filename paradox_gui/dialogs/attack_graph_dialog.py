"""Attack Graph dialog — визуализация цепочек атаки."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFont, QImage, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QGraphicsEllipseItem,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSlider,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
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
        self._report = report or {}
        self._graph = self._report.get("attack_graph", {}) or {}
        self._nodes = self._graph.get("nodes", [])
        self._edges = self._graph.get("edges", [])
        self._paths = self._graph.get("paths", [])
        self._impacts = set(self._graph.get("impact_targets", []))
        self._node_items: dict[str, QGraphicsEllipseItem] = {}
        self._edge_items: list[QGraphicsPathItem] = []
        self._t_min = 0.0
        self._t_max = 0.0
        self._play_timer = QTimer(self)
        self._play_timer.timeout.connect(self._on_play_tick)
        self.setWindowTitle("Граф атаки")
        self._build()
        self._draw()
        if self._paths:
            self._path_list.setCurrentRow(0)
        self.showMaximized()

    def showEvent(self, event):
        super().showEvent(event)
        # Вызываем fit ТОЛЬКО когда окно уже развернуто на весь экран
        self._view.fit()

    def _build(self):
        root = QHBoxLayout(self)

        # --- Левая панель: список путей ---
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

        # --- Центральная панель: легенда + граф + таймлайн ---
        self._scene = QGraphicsScene(self)
        self._view = _Zoomable(self._scene)

        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(0, 0, 0, 0)

        # Легенда
        legend_layout = QHBoxLayout()
        legend_layout.setContentsMargins(8, 4, 8, 4)
        legend_layout.setSpacing(16)
        legend_layout.addWidget(QLabel("<b>Легенда:</b>"))

        def _lbl(color, text):
            return QLabel(f"<span style='color:{color}; font-size:18px;'>●</span> {text}")

        legend_layout.addWidget(_lbl("#40c040", "Вход / Жертва"))
        legend_layout.addWidget(_lbl("#e0a040", "Pivot (Скомпрометирован)"))
        legend_layout.addWidget(_lbl("#e04040", "Impact / C2 (Цель)"))
        legend_layout.addSpacing(24)
        legend_layout.addWidget(QLabel("<span style='color:#a0a0b0;'>Линии: цвет = фаза kill-chain</span>"))
        legend_layout.addStretch(1)
        legend_layout.addWidget(QLabel("<i style='color:#808090; font-size:11px;'>Колесико мыши — масштаб | Зажать ЛКМ — перемещение</i>"))

        center_layout.addLayout(legend_layout)
        center_layout.addWidget(self._view, stretch=1)

        # Временная шкала (Time Machine)
        timeline_row = QHBoxLayout()
        timeline_row.setContentsMargins(0, 10, 0, 10)

        self._btn_play = QPushButton("\u25b6 \u0412\u043e\u0441\u043f\u0440\u043e\u0438\u0437\u0432\u0435\u0441\u0442\u0438")
        self._btn_play.setFixedWidth(160)
        self._btn_play.clicked.connect(self._toggle_play)
        timeline_row.addWidget(self._btn_play)

        self._time_slider = QSlider(Qt.Orientation.Horizontal)
        self._time_slider.setRange(0, 1000)
        self._time_slider.setValue(1000)
        self._time_slider.valueChanged.connect(self._on_time_changed)
        timeline_row.addWidget(self._time_slider, stretch=1)

        self._time_label = QLabel("\u2014")
        self._time_label.setStyleSheet("color: #a0a0b0; font-family: Consolas;")
        self._time_label.setFixedWidth(160)
        self._time_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        timeline_row.addWidget(self._time_label)

        center_layout.addLayout(timeline_row)

        # --- Правая панель: детали ---
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(8, 8, 8, 8)
        r_lbl = QLabel("\u0414\u0435\u0442\u0430\u043b\u0438 \u043f\u0443\u0442\u0438")
        r_lbl.setStyleSheet("font-weight: 600; font-size: 14px;")
        rv.addWidget(r_lbl)
        self._details = QTextBrowser()
        rv.addWidget(self._details, stretch=1)
        right.setFixedWidth(360)

        # --- Splitter ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(center_widget)
        splitter.addWidget(right)
        splitter.setSizes([340, 700, 340])
        root.addWidget(splitter, stretch=1)

        # --- Кнопка закрыть ---
        btn_row = QHBoxLayout()
        btn_row.addWidget(QLabel("<b>Экспорт:</b>"))
        btn_png = QPushButton("PNG")
        btn_png.clicked.connect(self._export_png)
        btn_row.addWidget(btn_png)
        btn_dot = QPushButton("DOT")
        btn_dot.clicked.connect(self._export_dot)
        btn_row.addWidget(btn_dot)
        btn_gml = QPushButton("GraphML")
        btn_gml.clicked.connect(self._export_graphml)
        btn_row.addWidget(btn_gml)
        btn_row.addStretch(1)
        btn = QPushButton("\u0417\u0430\u043a\u0440\u044b\u0442\u044c")
        btn.setObjectName("primary")
        btn.clicked.connect(self.accept)
        btn_row.addWidget(btn)
        root.addLayout(btn_row)

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
        sorted_phases = sorted(groups.keys())
        phase_to_x = {ph: idx * 320 for idx, ph in enumerate(sorted_phases)}

        for order in sorted_phases:
            bucket = groups[order]
            x = phase_to_x[order]
            for i, n in enumerate(bucket):
                # Больше отступ по Y, чтобы узлы не слипались
                y = (i - (len(bucket) - 1) / 2) * 160
                pos[n["ip"]] = (x, y)

        # v1.2.1: радиусы для обрезки стрелок
        nodes_by_ip = {n["ip"]: n for n in self._nodes}
        def _node_r(n):
            if not n:
                return 22.0
            r = 22.0
            if n.get("is_pivot") or n.get("is_impact"):
                r = 30.0
            if n.get("is_entry"):
                r = 28.0
            return r

        for e in self._edges:
            if e["src"] in pos and e["dst"] in pos:
                _sr = _node_r(nodes_by_ip.get(e["src"]))
                _dr = _node_r(nodes_by_ip.get(e["dst"]))
                self._draw_edge(pos[e["src"]], pos[e["dst"]], e, _sr, _dr)

        for n in self._nodes:
            if n["ip"] in pos:
                self._draw_node(pos[n["ip"]], n)

        self._setup_timeline()
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

        # Tooltip с деталями узла
        roles_str = ", ".join(n.get("roles", [])) or "—"
        from datetime import datetime
        def _fmt_ts(t):
            if not t:
                return "—"
            try:
                return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, ValueError):
                return str(t)
        tip_parts = [
            f"<b>{n['ip']}</b>",
            ("Внутренний" if n.get("is_internal") else "Внешний"),
            f"Роль: {roles_str}",
            f"Фаза: {n.get('phase_reached', '?')}",
            f"Findings: {n.get('findings_count', 0)}",
        ]
        if n.get("is_pivot"):
            tip_parts.append("<b>⚠ PIVOT</b>")
        if n.get("is_entry"):
            tip_parts.append("<b>ВХОД</b>")
        if n.get("is_impact"):
            tip_parts.append("<b>ЦЕЛЬ АТАКИ</b>")
        tip_parts.append(f"First seen: {_fmt_ts(n.get('first_ts'))}")
        tip_parts.append(f"Last seen: {_fmt_ts(n.get('last_ts'))}")
        item.setToolTip("<br>".join(tip_parts))

        # Двойной клик → история хоста
        ip_captured = n["ip"]
        def _on_dbl_click(event, _ip=ip_captured):
            self._open_host_story(_ip)
        item.mouseDoubleClickEvent = _on_dbl_click
        item.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable, True)

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

    def _draw_edge(self, src, dst, e, src_r: float = 22.0, dst_r: float = 22.0):
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
            f"{e['src']} → {e['dst']}\n"
            f"phase: {e.get('phase')}\n"
            f"findings: {', '.join(e.get('finding_types', []))}\n"
            f"severity: {e.get('severity')}  conf: {e.get('confidence', 0):.2f}"
        )
        self._scene.addItem(item)
        self._edge_items.append(item)

    def _open_host_story(self, ip: str):
        """Двойной клик на узле — история хоста."""
        try:
            from paradox.analyzers.story import build_host_story
            from paradox_gui.dialogs.host_story_dialog import HostStoryDialog
        except ImportError:
            return

        story = build_host_story(self._report, ip)
        dialog = HostStoryDialog(ip, story, self)
        dialog.exec()

    def _setup_timeline(self):
        """Найти границы времени и настроить слайдер."""
        times = []
        for n in self._nodes:
            if n.get("first_ts"):
                times.append(n["first_ts"])
            if n.get("last_ts"):
                times.append(n["last_ts"])
        for e in self._edges:
            if e.get("first_ts"):
                times.append(e["first_ts"])
            if e.get("last_ts"):
                times.append(e["last_ts"])

        if not times:
            self._time_slider.setEnabled(False)
            self._btn_play.setEnabled(False)
            self._time_label.setText("—")
            return

        self._t_min = min(times)
        self._t_max = max(times)

        # Если всё произошло в одну секунду, слайдер бесполезен
        if self._t_max - self._t_min < 1.0:
            self._time_slider.setEnabled(False)
            self._btn_play.setEnabled(False)
            self._update_time_label(self._t_max)
        else:
            self._time_slider.setEnabled(True)
            self._btn_play.setEnabled(True)
            self._on_time_changed(self._time_slider.value())

    def _update_time_label(self, ts: float):
        from datetime import datetime
        if not ts:
            self._time_label.setText("—")
            return
        try:
            dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            self._time_label.setText(dt)
        except (OSError, ValueError):
            self._time_label.setText(f"{ts:.0f}")

    def _on_time_changed(self, val: int):
        """Плавно скрываем то, что ещё не произошло."""
        if self._t_max <= self._t_min:
            return

        frac = val / 1000.0
        current_t = self._t_min + (self._t_max - self._t_min) * frac
        self._update_time_label(current_t)

        for n in self._nodes:
            item = self._node_items.get(n["ip"])
            if not item:
                continue
            # Узел виден, если его время наступило (или у него нет таймстампа)
            visible = (not n.get("first_ts")) or (n["first_ts"] <= current_t + 1.0)
            item.setOpacity(1.0 if visible else 0.05)

        for item, e in zip(self._edge_items, self._edges, strict=False):
            visible = (not e.get("first_ts")) or (e["first_ts"] <= current_t + 1.0)
            item.setOpacity(1.0 if visible else 0.05)

    def _toggle_play(self):
        if self._play_timer.isActive():
            self._play_timer.stop()
            self._btn_play.setText("▶ Воспроизвести")
        else:
            if self._time_slider.value() >= 1000:
                self._time_slider.setValue(0)
            self._play_timer.start(50)  # каждые 50 мс
            self._btn_play.setText("⏸ Пауза")

    def _on_play_tick(self):
        val = self._time_slider.value() + 5
        if val >= 1000:
            val = 1000
            self._play_timer.stop()
            self._btn_play.setText("▶ Воспроизвести")
        self._time_slider.setValue(val)

    def _export_png(self):
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
            QMessageBox.information(self, "Экспорт PNG", f"Успешно сохранено:\n{path}")
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
                if n.get("is_pivot"):
                    label += "\n(PIVOT)"
                lines.append(f'  "{n["ip"]}" [fillcolor="{color}", label="{label}"];')

            for e in self._edges:
                color = _PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a")
                label = ", ".join(e.get("finding_types", []))
                lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{label}", color="{color}"];')
            lines.append("}")
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            QMessageBox.information(self, "Экспорт DOT", f"Успешно сохранено:\n{path}")
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

            ET.SubElement(root, "key", id="label", **{"for": "all", "attr.name": "label", "attr.type": "string"})
            ET.SubElement(root, "key", id="severity", **{"for": "edge", "attr.name": "severity", "attr.type": "string"})

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
            QMessageBox.information(self, "Экспорт GraphML", f"Успешно сохранено:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта GraphML", str(e))

    def _on_select(self, row: int):
        if row < 0 or row >= len(self._paths):
            return
        path = self._paths[row]
        nodes_in = set(path.get("nodes", []))
        edges_in = {(e["src"], e["dst"]) for e in path.get("edges", [])}

        for ip, item in self._node_items.items():
            item.setOpacity(1.0 if ip in nodes_in else 0.15)
        for item in self._edge_items:
            _src, _dst = item.data(0), item.data(1)
            if (_src, _dst) in edges_in:
                item.setOpacity(1.0)
            else:
                item.setOpacity(0.25)

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
