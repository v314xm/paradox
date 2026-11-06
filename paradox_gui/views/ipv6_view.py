"""UI-виджет для IPv6 (NDP + потоки) с вертикальным QSplitter."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr


class IPv6View(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        # --- Верхняя часть: Сводка и Соседи (NDP) ---
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(6)

        self.lbl_summary = QLabel(tr("ipv6.no_data"))
        self.lbl_summary.setObjectName("sectionTitle")
        top_layout.addWidget(self.lbl_summary)

        self.table_neighbors = self._make_table(
            [tr("ipv6.col_ip"), tr("ipv6.col_mac"), tr("ipv6.col_role")],
            "ipv6Neighbors",
        )
        top_layout.addWidget(self.table_neighbors)
        splitter.addWidget(top_widget)

        # --- Нижняя часть: IPv6-Потоки ---
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(6)

        self.lbl_flows = QLabel(tr("ipv6.flows_title"))
        self.lbl_flows.setObjectName("sectionTitle")
        bottom_layout.addWidget(self.lbl_flows)

        self.table_flows = self._make_table(
            [tr("ipv6.col_src"), tr("ipv6.col_dst"), tr("ipv6.col_bytes")],
            "ipv6Flows",
        )
        bottom_layout.addWidget(self.table_flows)
        splitter.addWidget(bottom_widget)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

    @staticmethod
    def _make_table(headers: list[str], name: str) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setObjectName(name)
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        table.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        return table

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
            tr(
                "ipv6.summary",
                total=total,
                neighbors=len(neighbors),
                routers=len(routers),
            )
        )

        all_nodes = []
        for n in neighbors:
            all_nodes.append(
                (n.get("ip", ""), n.get("mac", ""), tr("ipv6.role_neighbor"))
            )
        for r_ip in routers:
            all_nodes.append((r_ip, "—", tr("ipv6.role_router")))

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
