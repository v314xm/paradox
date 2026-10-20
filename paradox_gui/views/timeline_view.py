"""Вкладка Kill-Chain Таймлайн (Умный парсинг v4)."""
import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

# Паттерн для поиска связи "IP -> IP" (с учетом возможных пробелов вокруг стрелки)
ARROW_REGEX = re.compile(r'((?:\d{1,3}\.){3}\d{1,3})\s*->\s*((?:\d{1,3}\.){3}\d{1,3})')
# Просто поиск IPv4 (для fallback)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

class TimelineView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        header_layout = QHBoxLayout()
        self.lbl_info = QLabel("Хронология инцидента по фазам Kill-Chain")
        self.lbl_info.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        header_layout.addWidget(self.lbl_info)
        header_layout.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск по IP, типу или MITRE...")
        self.search_edit.setMinimumWidth(300)
        self.search_edit.textChanged.connect(self._apply_filter)
        header_layout.addWidget(self.search_edit)

        self.btn_expand = QPushButton("Развернуть все")
        self.btn_expand.clicked.connect(lambda: self.tree.expandAll())
        header_layout.addWidget(self.btn_expand)

        self.btn_collapse = QPushButton("Свернуть все")
        self.btn_collapse.clicked.connect(lambda: self.tree.collapseAll())
        header_layout.addWidget(self.btn_collapse)

        layout.addLayout(header_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Событие", "Время", "Источник", "Назначение", "Детали", "Conf", "MITRE"
        ])
        self.tree.setAlternatingRowColors(True)
        self.tree.setSortingEnabled(False)

        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)

        self.tree.itemClicked.connect(self._on_item_clicked)
        splitter.addWidget(self.tree)

        self.details = QTextBrowser()
        self.details.setStyleSheet("background: #2a2a35; border: 1px solid #444; border-radius: 4px;")
        self.details.setHtml("<p style='color:#888;'>Кликните на событие, чтобы увидеть детали.</p>")
        self.details.setMinimumWidth(350)
        splitter.addWidget(self.details)

        splitter.setSizes([850, 350])

    def _extract_ips(self, text: str) -> tuple[str, str]:
        """Извлекает Source и Destination из текста."""
        # 1. Пытаемся найти четкий паттерн "IP -> IP"
        match = ARROW_REGEX.search(text)
        if match:
            return match.group(1), match.group(2)

        # 2. Если паттерна нет, берем первые два УНИКАЛЬНЫХ IP в тексте
        ips = IP_REGEX.findall(text)
        unique_ips = []
        for ip in ips:
            if ip not in unique_ips:
                unique_ips.append(ip)

        if len(unique_ips) >= 2:
            return unique_ips[0], unique_ips[1]
        elif len(unique_ips) == 1:
            return unique_ips[0], "—"
        return "—", "—"

    def update_data(self, report: dict):
        self.tree.clear()
        timeline = report.get("timeline", [])
        if not timeline:
            self.lbl_info.setText("Хронология инцидента (событий не найдено)")
            return

        self.lbl_info.setText(f"Хронология инцидента (Событий: {len(timeline)})")

        phases = {}
        for e in timeline:
            phase = e.get("phase", "Other")
            phases.setdefault(phase, []).append(e)

        sorted_phases = sorted(
            phases.keys(),
            key=lambda p: min(e.get("chain_order", 999) for e in phases[p])
        )

        t0 = min(e.get("ts", 0.0) for e in timeline)

        for phase_name in sorted_phases:
            events = phases[phase_name]

            phase_item = QTreeWidgetItem(self.tree)
            phase_item.setText(0, f"📁 {phase_name.upper()} ({len(events)})")
            font = QFont()
            font.setBold(True)
            phase_item.setFont(0, font)

            phase_colors = {
                "reconnaissance": "#44aaff",
                "execution": "#ffaa00",
                "persistence": "#ff8888",
                "lateral_movement": "#ff4444",
                "exfiltration": "#ff00ff",
                "impact": "#ff0000"
            }
            color = QColor(phase_colors.get(phase_name.lower(), "#888888"))
            phase_item.setForeground(0, QBrush(color))

            for e in events:
                child = QTreeWidgetItem(phase_item)

                ts = e.get("ts", 0.0)
                rel = ts - t0
                h = int(rel // 3600)
                m = int((rel % 3600) // 60)
                s = int(rel % 60)
                child.setText(1, f"{h}:{m:02d}:{s:02d}" if h > 0 else f"{m}:{s:02d}")

                kind = e.get("kind", "?")
                etype = e.get("type", "?")
                child.setText(0, f"{etype} ({kind})")

                # Пытаемся получить полный текст события
                full_text = f"{e.get('subject', '')} {e.get('description', '')} {e.get('value', '')}"
                src_ip, dst_ip = self._extract_ips(full_text)

                child.setText(2, src_ip)
                child.setText(3, dst_ip)

                # Детали
                desc = str(e.get("description") or "")
                child.setText(4, desc)

                conf = e.get("confidence")
                if isinstance(conf, (int, float)):
                    child.setText(5, f"{conf:.2f}")
                    if conf >= 0.85:
                        child.setForeground(5, QBrush(QColor("#ff4444")))
                    elif conf >= 0.7:
                        child.setForeground(5, QBrush(QColor("#ffaa00")))
                else:
                    child.setText(5, "—")

                child.setText(6, str(e.get("mitre_id") or "—"))

                child.setData(0, Qt.ItemDataRole.UserRole, e)

        self.tree.expandAll()

    def _on_item_clicked(self, item: QTreeWidgetItem, column: int):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            self.details.setHtml("<p style='color:#888;'>Выбрана фаза. Кликните на конкретное событие.</p>")
            return

        html = f"<h2 style='color:#44aaff; margin-bottom:5px;'>{data.get('type', '?')}</h2>"
        html += f"<p><b>Фаза:</b> {data.get('phase', '?')}</p>"

        mitre = data.get('mitre_id')
        html += f"<p><b>MITRE:</b> {mitre if mitre else '—'}</p>"

        conf = data.get("confidence", 0)
        conf_color = "#ff4444" if conf >= 0.85 else "#ffaa00" if conf >= 0.7 else "#44aaff"
        html += f"<p><b>Confidence:</b> <span style='color:{conf_color}; font-weight:bold;'>{conf:.2f}</span></p>"

        reasons = data.get("confidence_reasons") or []
        if reasons:
            html += "<h4 style='color:#aaa;'>Почему детектор так решил:</h4><ul>"
            for r in reasons:
                html += f"<li>{r}</li>"
            html += "</ul>"

        ev = data.get("evidence") or {}
        if ev:
            html += "<h4 style='color:#aaa;'>Дополнительные данные (Evidence):</h4><ul>"
            for k, v in ev.items():
                html += f"<li><b>{k}:</b> {v}</li>"
            html += "</ul>"

        html += f"<hr><h4 style='color:#aaa;'>Полное описание:</h4><p style='line-height:1.4;'>{data.get('description', '')}</p>"

        self.details.setHtml(html)

    def _apply_filter(self, text: str):
        text = text.lower()
        root = self.tree.invisibleRootItem()

        def filter_item(item):
            matches = False
            if not text:
                matches = True
            else:
                for col in range(self.tree.columnCount()):
                    if text in item.text(col).lower():
                        matches = True
                        break

            child_visible = False
            for i in range(item.childCount()):
                if filter_item(item.child(i)):
                    child_visible = True

            visible = matches or child_visible
            item.setHidden(not visible)

            if visible and item.childCount() > 0 and text:
                item.setExpanded(True)

            return visible

        for i in range(root.childCount()):
            filter_item(root.child(i))
