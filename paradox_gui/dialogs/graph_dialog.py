"""Окно визуализации графа связей (Мега-версия)."""
import math
import traceback
from datetime import datetime as dt

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSlider,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr
from paradox_gui.theme import PALETTE, SEVERITY

# Попытка импортировать диалог истории хоста
try:
    from paradox.analyzers.story import build_host_story
    from paradox_gui.dialogs.host_story_dialog import HostStoryDialog
    HAS_STORY = True
except ImportError:
    HAS_STORY = False


class ZoomableView(QGraphicsView):
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self._scene = scene
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setObjectName("graphCanvas")
        self.setBackgroundBrush(QColor(PALETTE["bg"]))

    def wheelEvent(self, event):
        zoom_factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(zoom_factor, zoom_factor)

    def fit_in_view(self):
        rect = self._scene.itemsBoundingRect()
        if not rect.isNull() and rect.width() > 0 and rect.height() > 0:
            self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)


class InteractiveNode(QGraphicsEllipseItem):
    def __init__(self, x, y, r, ip, roles, total_bytes, dialog):
        super().__init__(x - r, y - r, r * 2, r * 2)
        self.ip = ip
        self.dialog = dialog
        roles = roles or []
        total_bytes = total_bytes or 0

        if "/" in ip:
            color = QColor(PALETTE["text_muted"])
        elif "role_deviation" in roles:
            color = QColor(PALETTE["danger"])
        elif "pivot" in roles or "attacker_candidate" in roles:
            color = QColor(PALETTE["danger"])
        elif "victim_candidate" in roles:
            color = QColor(SEVERITY["high"])
        elif x < 300:
            color = QColor(PALETTE["accent"])
        else:
            color = QColor(PALETTE["text_muted"])

        self.default_brush = QBrush(color)
        self.setBrush(self.default_brush)
        self.setPen(QPen(QColor(PALETTE["text"]), 1.5))

        roles_str = ", ".join(roles) if roles else "—"
        self.setToolTip(tr(
            "graph.node_tip",
            ip=ip,
            roles=roles_str,
            nbytes=f"{total_bytes:,}",
        ))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)

    def mousePressEvent(self, event):
        self.dialog.highlight_node(self.ip)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        # Узлы-подсети ("10.0.0.0/24") — не хосты, истории у них нет.
        if "/" not in self.ip and HAS_STORY:
            self.dialog.open_host_story(self.ip)
        super().mouseDoubleClickEvent(event)


class InteractiveEdge(QGraphicsPathItem):
    def __init__(self, x1, y1, x2, y2, bytes_count, proto, port, src_ip, dst_ip, index, ts=None):
        super().__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ts = ts or 0.0
        bytes_count = bytes_count or 0

        path = QPainterPath()
        path.moveTo(x1, y1)
        offset = (index % 5) * 20 - 40
        cx = (x1 + x2) / 2
        cy = (y1 + y2) / 2 - 50 + offset
        path.quadTo(cx, cy, x2, y2)
        self.setPath(path)

        pen_width = max(1.0, min(8.0, math.log10(bytes_count + 10) - 1))
        self.default_pen = QPen(QColor(PALETTE["border"]), pen_width)
        self.highlight_pen = QPen(QColor(PALETTE["text"]), pen_width + 2)

        if "Finding" in str(proto):
            self.default_pen = QPen(
                QColor(PALETTE["danger"]), 2, Qt.PenStyle.DashLine
            )
            self.highlight_pen = QPen(
                QColor(PALETTE["danger_light"]), 3, Qt.PenStyle.DashLine
            )

        self.setPen(self.default_pen)

        port_str = f":{port}" if port else ""
        self.setToolTip(tr(
            "graph.edge_tip",
            proto=proto,
            port=port_str,
            nbytes=f"{bytes_count:,}",
        ))


class GraphDialog(QDialog):
    def __init__(self, report: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("graphDialog")
        self.setWindowTitle(tr("graph.title"))
        self.resize(1280, 820)
        self.setMinimumSize(960, 640)
        self.report = report or {}

        self.nodes = {}
        self.edges = []
        self.edges_by_ip = {}
        self.node_times = {}

        self.t_min = 0.0
        self.t_max = 0.0

        self._build_ui()

    def _build_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Панель фильтров
        filter_layout = QHBoxLayout()
        self.cb_only_findings = QCheckBox(tr("graph.only_findings"))
        self.cb_only_findings.stateChanged.connect(self._redraw_graph)
        filter_layout.addWidget(self.cb_only_findings)

        self.cb_hide_isolated = QCheckBox(tr("graph.hide_isolated"))
        self.cb_hide_isolated.stateChanged.connect(self._redraw_graph)
        filter_layout.addWidget(self.cb_hide_isolated)

        filter_layout.addStretch()
        left_layout.addLayout(filter_layout)

        self.scene = QGraphicsScene(self)
        self.view = ZoomableView(self.scene)
        left_layout.addWidget(self.view)

        # Панель времени
        time_layout = QHBoxLayout()
        self.lbl_time = QLabel(tr("graph.time"))
        self.lbl_time.setObjectName("timeLabel")
        time_layout.addWidget(self.lbl_time)

        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 100)
        self.slider.setValue(100)
        self.slider.valueChanged.connect(self._on_time_changed)
        time_layout.addWidget(self.slider)

        left_layout.addLayout(time_layout)

        # Правая панель
        right_widget = QWidget()
        right_widget.setMinimumWidth(320)
        right_widget.setMaximumWidth(440)
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(10, 0, 0, 0)

        self.info_panel = QTextBrowser()
        self.info_panel.setObjectName("graphInfo")
        self.info_panel.setHtml(
            f"<p style='color:{PALETTE['text_muted']};'>"
            f"{tr('graph.tip')}<br>"
            f"{tr('graph.tip_dblclick')}"
            f"</p>"
        )
        right_layout.addWidget(self.info_panel)

        legend = QLabel(
            f"{tr('graph.legend_title')}<br>"
            f"<span style='color:{PALETTE['danger']};'>●</span> {tr('graph.legend_attacker')}<br>"
            f"<span style='color:{PALETTE['danger']};'>◉</span> {tr('graph.legend_role_deviation')}<br>"
            f"<span style='color:{SEVERITY['high']};'>●</span> {tr('graph.legend_victim')}<br>"
            f"<span style='color:{PALETTE['accent']};'>●</span> {tr('graph.legend_internal')}<br>"
            f"<span style='color:{PALETTE['text_muted']};'>●</span> {tr('graph.legend_external')}<br>"
            f"<span style='color:{PALETTE['text_muted']};'>●</span> {tr('graph.legend_subnet')}<br>"
            f"<span style='color:{PALETTE['danger']};'>- - -</span> {tr('graph.legend_finding')}<br>"
        )
        legend.setObjectName("graphLegend")
        right_layout.addWidget(legend)

        btn_row = QHBoxLayout()
        btn_reset = QPushButton(tr("graph.reset"))
        btn_reset.setObjectName("small")
        btn_reset.clicked.connect(self.reset_highlight)
        btn_close = QPushButton(tr("graph.close"))
        btn_close.setDefault(True)
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_reset)
        btn_row.addStretch(1)
        btn_row.addWidget(btn_close)
        right_layout.addLayout(btn_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setSizes([900, 360])
        layout.addWidget(splitter)

        self._draw_graph()
        self.view.fit_in_view()

    def _redraw_graph(self):
        """Перерисовать граф с учетом фильтров."""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.edges_by_ip.clear()
        self.node_times.clear()
        self._draw_graph()
        self._on_time_changed(self.slider.value())

    def _get_subnet(self, ip: str) -> str:
        """Вернуть /24 подсеть для IPv4, или сам IP для IPv6."""
        if ":" in ip: return ip
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip

    def _draw_graph(self):
        try:
            hide_isolated = self.cb_hide_isolated.isChecked()
            only_findings = self.cb_only_findings.isChecked()

            entities = self.report.get("entities") or {}
            internal = entities.get("internal") or []
            external = entities.get("external") or []
            flows_dict = self.report.get("flows") or {}
            flows = flows_dict.get("top_by_bytes") or []
            findings = self.report.get("findings") or []

            times = [f.get("first_seen") for f in findings if f.get("first_seen")]
            self.t_min = min(times) if times else 0.0
            self.t_max = max(times) if times else 1.0
            if self.t_min == self.t_max: self.t_max += 1.0

            # Сбор трафика
            traffic_map = {}
            for f in flows:
                src, dst = f.get("src_ip"), f.get("dst_ip")
                b = f.get("bytes") or 0
                if src: traffic_map[src] = traffic_map.get(src, 0) + b
                if dst: traffic_map[dst] = traffic_map.get(dst, 0) + b

            finding_ips = set()
            for f in findings:
                if f.get("src_ip"): finding_ips.add(f.get("src_ip"))
                if f.get("dst_ip"): finding_ips.add(f.get("dst_ip"))

            # «Только findings»: узлы и рёбра без привязки к находкам
            # не рисуем. Кластеры внешних IP проверяем по подсети.
            if only_findings:
                finding_subnets = {self._get_subnet(ip) for ip in finding_ips}
                internal = [
                    e for e in internal if e.get("ip") in finding_ips
                ]
                external = [
                    e for e in external
                    if e.get("ip") in finding_ips
                    or self._get_subnet(e.get("ip", "")) in finding_subnets
                ]
                flows = [
                    f for f in flows
                    if f.get("src_ip") in finding_ips
                    or f.get("dst_ip") in finding_ips
                ]

            # Кластеризация внешних IP по /24
            external_clustered = {}
            for e in external:
                ip = e.get("ip")
                if not ip: continue
                subnet = self._get_subnet(ip)
                if subnet not in external_clustered:
                    external_clustered[subnet] = {"roles": [], "bytes": 0, "ips": []}
                external_clustered[subnet]["roles"].extend(e.get("roles") or [])
                external_clustered[subnet]["bytes"] += traffic_map.get(ip, 0)
                external_clustered[subnet]["ips"].append(ip)

            # Преобразуем в список для сортировки
            ext_nodes = []
            for subnet, data in external_clustered.items():
                ext_nodes.append({
                    "ip": subnet,
                    "roles": list(set(data["roles"])),
                    "bytes": data["bytes"],
                    "is_cluster": len(data["ips"]) > 1
                })
            ext_nodes.sort(key=lambda x: x["bytes"], reverse=True)

            MAX_EXTERNAL = 40
            ext_nodes = ext_nodes[:MAX_EXTERNAL]

            internal.sort(key=lambda e: traffic_map.get(e.get("ip"), 0), reverse=True)
            node_data = {}

            # Внутренние
            for i, e in enumerate(internal):
                ip = e.get("ip")
                if not ip: continue
                total_b = traffic_map.get(ip, 0)
                r = min(35, max(15, 15 + math.log10(total_b + 10) * 2))
                if ip in finding_ips: r = max(r, 22)
                y = (i - len(internal)/2) * 120 + 500
                node_data[ip] = {"x": 150, "y": y, "r": r, "roles": e.get("roles") or [], "bytes": total_b}

            # Внешние (кластеры)
            cols = 5
            for i, e in enumerate(ext_nodes):
                ip = e["ip"]
                total_b = e["bytes"]
                r = min(30, max(12, 12 + math.log10(total_b + 10) * 2))
                if ip in finding_ips: r = max(r, 18)

                col = i % cols
                row = i // cols
                x = 550 + col * 130
                y = 200 + row * 90

                node_data[ip] = {"x": x, "y": y, "r": r, "roles": e["roles"], "bytes": total_b, "is_cluster": e["is_cluster"]}

            # Ребра
            active_edges_count = 0
            for idx, f in enumerate(flows):
                src, dst = f.get("src_ip"), f.get("dst_ip")
                if not src or not dst: continue

                # Мапим dst_ip на подсеть, если нужно
                dst_node = self._get_subnet(dst) if dst in [x["ip"] for x in external] else dst

                if src in node_data and dst_node in node_data:
                    n1, n2 = node_data[src], node_data[dst_node]
                    port = f.get("dst_port")
                    edge_ts = max(self.node_times.get(src, self.t_min), self.node_times.get(dst_node, self.t_min))
                    edge = InteractiveEdge(n1["x"], n1["y"], n2["x"], n2["y"], f.get("bytes"), f.get("proto", "?"), port, src, dst_node, idx, ts=edge_ts)
                    self.scene.addItem(edge)
                    self.edges.append(edge)
                    self.edges_by_ip.setdefault(src, []).append(edge)
                    self.edges_by_ip.setdefault(dst_node, []).append(edge)
                    active_edges_count += 1

            # Ребра из Findings
            for idx, f in enumerate(findings):
                src, dst = f.get("src_ip"), f.get("dst_ip")
                if not src or not dst: continue

                dst_node = self._get_subnet(dst) if dst in [x["ip"] for x in external] else dst

                if src in node_data and dst_node in node_data and src != dst_node:
                    n1, n2 = node_data[src], node_data[dst_node]
                    edge = InteractiveEdge(n1["x"], n1["y"], n2["x"], n2["y"], 10, f"Finding: {f.get('type')}", None, src, dst_node, idx, ts=f.get("first_seen"))
                    self.scene.addItem(edge)
                    self.edges.append(edge)
                    self.edges_by_ip.setdefault(src, []).append(edge)
                    self.edges_by_ip.setdefault(dst_node, []).append(edge)

            # Время появления узлов (мин. время среди его находок)
            for ip in node_data:
                ip_findings = [f.get("first_seen") for f in findings if f.get("src_ip") == ip or f.get("dst_ip") == ip]
                self.node_times[ip] = min(ip_findings) if ip_findings else self.t_min

            # Отрисовка узлов
            for ip, data in node_data.items():
                # Фильтр изолированных
                if hide_isolated and ip not in self.edges_by_ip:
                    continue

                node = InteractiveNode(data["x"], data["y"], data["r"], ip, data["roles"], data["bytes"], self)
                self.scene.addItem(node)
                self.nodes[ip] = node

                # Текст
                display_ip = ip
                if data.get("is_cluster") and "/" in ip:
                    display_ip = ip.split('/')[0] + ".x"

                text = QGraphicsTextItem(display_ip)
                text.setDefaultTextColor(QColor(PALETTE["text"]))
                text.setFont(QFont("Consolas", 9))
                rect = text.boundingRect()
                text.setPos(data["x"] - rect.width()/2, data["y"] + data["r"] + 5)
                self.scene.addItem(text)

            self.scene.setSceneRect(self.scene.itemsBoundingRect())
        except Exception as e:
            err = traceback.format_exc()
            self.info_panel.setHtml(
                f"<h3 style='color:{PALETTE['danger']};'>"
                f"{tr('graph.render_error')}</h3><pre>{err}</pre>"
            )

    def open_host_story(self, ip: str):
        """Открыть окно истории хоста при двойном клике."""
        if not HAS_STORY:
            return
        story = build_host_story(self.report, ip)
        dialog = HostStoryDialog(ip, story, self)
        dialog.exec()

    def _on_time_changed(self, value: int):
        current_t = self.t_min + (self.t_max - self.t_min) * (value / 100.0)
        try:
            time_str = dt.fromtimestamp(current_t).strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, ValueError, OverflowError):
            time_str = f"{current_t:.1f}"
        self.lbl_time.setText(tr("graph.time_value", time=time_str))

        for ip, node in self.nodes.items():
            node_t = self.node_times.get(ip, self.t_min)
            node.setOpacity(0.05 if node_t > current_t else 1.0)

        for edge in self.edges:
            edge.setOpacity(0.05 if edge.ts > current_t else 1.0)

    def highlight_node(self, ip: str):
        self._on_time_changed(self.slider.value())

        for edge in self.edges:
            edge.setPen(edge.default_pen)
            if edge.src_ip != ip and edge.dst_ip != ip:
                edge.setOpacity(0.05)

        for n_ip, node in self.nodes.items():
            if n_ip != ip:
                node.setOpacity(0.1)

        if ip in self.nodes:
            self.nodes[ip].setOpacity(1.0)
            self.nodes[ip].setBrush(QBrush(QColor(PALETTE["text"])))

        findings = self.report.get("findings") or []
        ip_findings = [f for f in findings if f.get("src_ip") == ip or f.get("dst_ip") == ip]
        ip_findings.sort(key=lambda x: x.get("first_seen", 0))

        html = f"<h3>{ip}</h3>"

        if ip in self.edges_by_ip:
            for edge in self.edges_by_ip[ip]:
                neighbor = edge.dst_ip if edge.src_ip == ip else edge.src_ip
                edge.setPen(edge.highlight_pen)
                edge.setOpacity(1.0)
                if neighbor in self.nodes:
                    self.nodes[neighbor].setOpacity(1.0)

        if ip_findings:
            html += f"{tr('graph.events')}<ul style='line-height: 1.4;'>"
            for f in ip_findings:
                ts = f.get("first_seen")
                t_str = dt.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "??:??"
                html += f"<li><span style='color:{SEVERITY['high']};'>[{t_str}]</span> {f.get('type')}</li>"
            html += "</ul>"
        else:
            html += (
                f"<p style='color:{PALETTE['text_muted']};'>"
                f"{tr('graph.no_findings')}</p>"
            )

        # role_deviation: поведение хоста противоречит базовой роли.
        rd = self._role_deviation_for(ip)
        if rd:
            sev_color = SEVERITY.get(rd.get("severity", "medium"), SEVERITY["medium"])
            html += (
                f"<p style='color:{sev_color};'>⚠ {tr('graph.role_deviation')}</p>"
            )
            hint = rd.get("resolution_hint")
            if hint:
                html += f"<p style='color:{PALETTE['text_muted']};'>{hint}</p>"

        self.info_panel.setHtml(html)

    def _role_deviation_for(self, ip: str) -> dict | None:
        """Противоречие role_deviation для IP (если есть)."""
        for c in self.report.get("contradictions") or []:
            if c.get("rule") == "role_deviation" and c.get("subject") == ip:
                return c
        return None

    def reset_highlight(self):
        self.slider.setValue(100)
        for edge in self.edges:
            edge.setPen(edge.default_pen)
        for node in self.nodes.values():
            node.setBrush(node.default_brush)
        self.info_panel.setHtml(
            f"<p style='color:{PALETTE['text_muted']};'>"
            f"{tr('graph.click_node')}</p>"
        )
