"""Панель аномалий (оборванные сессии)."""
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QHeaderView, QTabWidget, QWidget
)

class AbsencePanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._build_ui()
        self.setVisible(False)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        title = QLabel("Аномалии / Оборванные сессии")
        title.setObjectName("h1")
        layout.addWidget(title)

        self.tabs = QTabWidget()

        # Вкладка 1: DNS без ответа
        self.tab_dns = QWidget()
        vbox_dns = QVBoxLayout(self.tab_dns)
        vbox_dns.setContentsMargins(0, 0, 0, 0)
        self.table_dns = QTableWidget(0, 2)
        self.table_dns.setHorizontalHeaderLabels(["Домен (QNAME)", "Кол-во запросов"])
        self.table_dns.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_dns.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vbox_dns.addWidget(self.table_dns)
        self.tabs.addTab(self.tab_dns, "DNS без ответа")

        # Вкладка 2: TCP без ответа
        self.tab_tcp = QWidget()
        vbox_tcp = QVBoxLayout(self.tab_tcp)
        vbox_tcp.setContentsMargins(0, 0, 0, 0)
        self.table_tcp = QTableWidget(0, 4)
        self.table_tcp.setHorizontalHeaderLabels(["Src IP", "Dst IP", "Порт", "Пакеты"])
        self.table_tcp.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_tcp.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vbox_tcp.addWidget(self.table_tcp)
        self.tabs.addTab(self.tab_tcp, "TCP без ответа (SYN)")

        layout.addWidget(self.tabs)

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
