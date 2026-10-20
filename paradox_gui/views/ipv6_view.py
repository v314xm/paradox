"""UI-виджет для IPv6 (NDP + потоки) с вертикальным QSplitter."""
try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QSplitter, QTableWidget, 
        QTableWidgetItem, QLabel, QHeaderView
    )
    from PySide6.QtCore import Qt
except ImportError:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QSplitter, QTableWidget, 
        QTableWidgetItem, QLabel, QHeaderView
    )
    from PyQt5.QtCore import Qt


class IPv6View(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        # --- Верхняя часть: Сводка и Соседи (NDP) ---
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)

        self.lbl_summary = QLabel("IPv6: Нет данных")
        self.lbl_summary.setStyleSheet("font-weight: bold; font-size: 14px; padding: 5px;")
        top_layout.addWidget(self.lbl_summary)

        self.table_neighbors = QTableWidget(0, 3)
        self.table_neighbors.setHorizontalHeaderLabels(["IPv6 Адрес", "MAC-адрес", "Роль"])
        self.table_neighbors.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_neighbors.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        top_layout.addWidget(self.table_neighbors)

        splitter.addWidget(top_widget)

        # --- Нижняя часть: IPv6-Потоки ---
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)

        self.lbl_flows = QLabel("IPv6 Потоки (Top by Bytes)")
        self.lbl_flows.setStyleSheet("font-weight: bold; padding: 5px;")
        bottom_layout.addWidget(self.lbl_flows)

        self.table_flows = QTableWidget(0, 3)
        self.table_flows.setHorizontalHeaderLabels(["Src IPv6", "Dst IPv6", "Bytes"])
        self.table_flows.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_flows.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        bottom_layout.addWidget(self.table_flows)

        splitter.addWidget(bottom_widget)

        # Пропорции
        splitter.setSizes([400, 400])

    def update_data(self, report: dict):
        """Обновление данных из итогового JSON (report)."""
        if not isinstance(report, dict):
            return

        # 1. Обновляем NDP (Соседи и Роутеры)
        ndp = report.get("ndp", {})
        total = ndp.get("total", 0)
        neighbors = ndp.get("neighbors", [])
        routers = ndp.get("routers", [])

        self.lbl_summary.setText(
            f"Всего NDP-пакетов: {total} | "
            f"Соседей: {len(neighbors)} | "
            f"Роутеров: {len(routers)}"
        )

        all_nodes = []
        for n in neighbors:
            all_nodes.append((n.get("ip", ""), n.get("mac", ""), "Сосед (NDP)"))
        for r_ip in routers:
            all_nodes.append((r_ip, "—", "Роутер (RA)"))

        self.table_neighbors.setRowCount(len(all_nodes))
        for row, (ip, mac, role) in enumerate(all_nodes):
            self.table_neighbors.setItem(row, 0, QTableWidgetItem(ip))
            self.table_neighbors.setItem(row, 1, QTableWidgetItem(mac))
            self.table_neighbors.setItem(row, 2, QTableWidgetItem(role))

        # 2. Обновляем IPv6-потоки
        # Берем из report["flows"]["top_by_bytes"] согласно контракту
        flows_data = report.get("flows", {}).get("top_by_bytes", [])

        ipv6_flows = [
            f for f in flows_data 
            if ":" in str(f.get("src_ip", "")) or ":" in str(f.get("dst_ip", ""))
        ]

        self.table_flows.setRowCount(len(ipv6_flows))
        for row, f in enumerate(ipv6_flows):
            self.table_flows.setItem(row, 0, QTableWidgetItem(str(f.get("src_ip", ""))))
            self.table_flows.setItem(row, 1, QTableWidgetItem(str(f.get("dst_ip", ""))))
            self.table_flows.setItem(row, 2, QTableWidgetItem(str(f.get("bytes", 0))))
