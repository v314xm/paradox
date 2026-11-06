"""Панель аномалий (оборванные сессии)."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHeaderView,
    QLabel,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr


class AbsencePanel(QFrame):
    # Минимум таблицы: ~8 строк видны сразу, без скролла внутри вкладки.
    _MIN_TABLE_HEIGHT = 280

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Expanding,
        )
        self._build_ui()
        self.setVisible(False)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        title = QLabel(tr("abs.title"))
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("cardTabs")

        # Вкладка 1: DNS без ответа
        self.tab_dns = QWidget()
        vbox_dns = QVBoxLayout(self.tab_dns)
        vbox_dns.setContentsMargins(0, 0, 0, 0)
        self.table_dns = self._make_table(
            [tr("abs.col.qname"), tr("abs.col.requests")]
        )
        vbox_dns.addWidget(self.table_dns)
        self.tabs.addTab(self.tab_dns, tr("abs.dns"))

        # Вкладка 2: TCP без ответа
        self.tab_tcp = QWidget()
        vbox_tcp = QVBoxLayout(self.tab_tcp)
        vbox_tcp.setContentsMargins(0, 0, 0, 0)
        self.table_tcp = self._make_table(
            [tr("abs.col.src"), tr("abs.col.dst"),
             tr("abs.col.port"), tr("abs.col.packets")]
        )
        vbox_tcp.addWidget(self.table_tcp)
        self.tabs.addTab(self.tab_tcp, tr("abs.tcp"))

        layout.addWidget(self.tabs)

    def _make_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setObjectName("absTable")
        table.setMinimumHeight(self._MIN_TABLE_HEIGHT)
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

    def update_report(self, report: dict):
        absence = report.get("absence", {})
        dns_data = absence.get("dns_unanswered", [])
        tcp_data = absence.get("tcp_unanswered", [])

        if not dns_data and not tcp_data:
            self.setVisible(False)
            return

        self.setVisible(True)

        # DNS
        self.table_dns.setRowCount(len(dns_data))
        for row, item in enumerate(dns_data):
            self.table_dns.setItem(row, 0, QTableWidgetItem(str(item.get("qname", ""))))
            self.table_dns.setItem(row, 1, QTableWidgetItem(str(item.get("count", ""))))

        # TCP
        self.table_tcp.setRowCount(len(tcp_data))
        for row, item in enumerate(tcp_data):
            self.table_tcp.setItem(row, 0, QTableWidgetItem(str(item.get("src_ip", ""))))
            self.table_tcp.setItem(row, 1, QTableWidgetItem(str(item.get("dst_ip", ""))))
            self.table_tcp.setItem(row, 2, QTableWidgetItem(str(item.get("dst_port", ""))))
            self.table_tcp.setItem(row, 3, QTableWidgetItem(str(item.get("packets", ""))))

        # Показываем только ту вкладку, где есть данные
        if not dns_data:
            self.tabs.setCurrentIndex(1)
        elif not tcp_data:
            self.tabs.setCurrentIndex(0)
