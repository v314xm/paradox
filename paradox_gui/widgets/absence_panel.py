"""Панель аномалий: DNS без ответа, TCP без ответа и объём по хостам."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
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

from paradox_gui.formatting import fmt_bytes, fmt_count
from paradox_gui.i18n import tr

#: Сколько хостов показывать в «Объёме»: дальше это уже таблица flows.
_VOLUME_TOP = 20
#: «Выброс» — втрое больше медианы по захвату, но не меньше мегабайта.
_SPIKE_RATIO = 3.0
_SPIKE_MIN_BYTES = 1024 * 1024

# Колонки вкладки «Объём по хостам».
V_HOST, V_UP, V_DOWN, V_SHARE, V_FLOWS, V_FLAG = range(6)


class AbsencePanel(QFrame):
    #: Двойной клик по строке объёма — история выбранного хоста.
    host_story_requested = Signal(str)

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

        # Вкладка 3: объём по внутренним хостам
        self.tab_volume = QWidget()
        vbox_volume = QVBoxLayout(self.tab_volume)
        vbox_volume.setContentsMargins(0, 0, 0, 0)
        vbox_volume.setSpacing(4)

        hint = QLabel(tr("abs.volume.hint"))
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        vbox_volume.addWidget(hint)

        self.table_volume = self._make_table(
            [tr("abs.col.host"), tr("abs.col.up"), tr("abs.col.down"),
             tr("abs.col.share"), tr("abs.col.flows"), tr("abs.col.flag")]
        )
        self.table_volume.cellDoubleClicked.connect(
            self._on_volume_activated
        )
        vbox_volume.addWidget(self.table_volume)
        self._volume_tab_index = self.tabs.addTab(
            self.tab_volume, tr("abs.volume"),
        )
        self.tabs.setTabVisible(self._volume_tab_index, False)

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
        absence = report.get("absence", {}) or {}
        dns_data = absence.get("dns_unanswered", []) or []
        tcp_data = absence.get("tcp_unanswered", []) or []
        volume_rows, total_up, median = self._volume_stats(report)

        if not dns_data and not tcp_data and not volume_rows:
            self.setVisible(False)
            return

        self.setVisible(True)

        # DNS
        self.table_dns.setRowCount(len(dns_data))
        for row, item in enumerate(dns_data):
            self.table_dns.setItem(
                row, 0, QTableWidgetItem(str(item.get("qname", "")))
            )
            self.table_dns.setItem(
                row, 1, QTableWidgetItem(str(item.get("count", "")))
            )

        # TCP
        self.table_tcp.setRowCount(len(tcp_data))
        for row, item in enumerate(tcp_data):
            self.table_tcp.setItem(
                row, 0, QTableWidgetItem(str(item.get("src_ip", "")))
            )
            self.table_tcp.setItem(
                row, 1, QTableWidgetItem(str(item.get("dst_ip", "")))
            )
            self.table_tcp.setItem(
                row, 2, QTableWidgetItem(str(item.get("dst_port", "")))
            )
            self.table_tcp.setItem(
                row, 3, QTableWidgetItem(str(item.get("packets", "")))
            )

        self._fill_volume(volume_rows, total_up, median)

        # Показываем вкладку объёма только когда есть что показывать.
        self.tabs.setTabVisible(
            self._volume_tab_index, bool(volume_rows),
        )
        self._focus_data_tab(
            (bool(dns_data), bool(tcp_data), bool(volume_rows))
        )

    @staticmethod
    def _volume_stats(report: dict) -> tuple[list[dict], int, float]:
        """Хосты по объёму: строки, сумма отправленного, медиана."""
        entities = report.get("entities", {}) or {}
        internal = [
            e for e in (entities.get("internal") or [])
            if isinstance(e, dict) and e.get("ip")
        ]

        rows: list[dict] = []
        for entity in internal:
            up = int(entity.get("bytes_out") or 0)
            down = int(entity.get("bytes_in") or 0)
            if up + down <= 0:
                continue
            rows.append({
                "ip": str(entity["ip"]),
                "up": up,
                "down": down,
                "flows": (
                    int(entity.get("flows_out") or 0)
                    + int(entity.get("flows_in") or 0)
                ),
            })
        if not rows:
            return [], 0, 0.0

        rows.sort(key=lambda r: (-max(r["up"], r["down"]), r["ip"]))
        total_up = sum(r["up"] for r in rows)

        volumes = sorted(max(r["up"], r["down"]) for r in rows)
        middle = len(volumes) // 2
        median = (
            volumes[middle] if len(volumes) % 2
            else (volumes[middle - 1] + volumes[middle]) / 2
        )
        return rows[:_VOLUME_TOP], total_up, float(median)

    def _fill_volume(
        self, rows: list[dict], total_up: int, median: float,
    ) -> None:
        self.table_volume.setRowCount(len(rows))
        for index, row in enumerate(rows):
            value = max(row["up"], row["down"])
            ratio = value / median if median else 0.0
            flag = ""
            if ratio >= _SPIKE_RATIO and value >= _SPIKE_MIN_BYTES:
                flag = tr("abs.volume.spike", ratio=ratio)
            share = f"{row['up'] / total_up:.0%}" if total_up else "—"

            cells = (
                row["ip"],
                fmt_bytes(row["up"]),
                fmt_bytes(row["down"]),
                share,
                fmt_count(row["flows"]),
                flag,
            )
            for column, text in enumerate(cells):
                self.table_volume.setItem(
                    index, column, QTableWidgetItem(text)
                )

    def _focus_data_tab(self, present: tuple[bool, bool, bool]) -> None:
        current = self.tabs.currentIndex()
        if 0 <= current < len(present) and present[current]:
            return
        for index, has_data in enumerate(present):
            if has_data:
                self.tabs.setCurrentIndex(index)
                return

    def _on_volume_activated(self, row: int, _column: int) -> None:
        item = self.table_volume.item(row, V_HOST)
        if item is not None and item.text():
            self.host_story_requested.emit(item.text())

    def clear(self) -> None:
        """Сбросить таблицы перед новым прогоном."""
        self.table_dns.setRowCount(0)
        self.table_tcp.setRowCount(0)
        self.table_volume.setRowCount(0)
        self.tabs.setTabVisible(self._volume_tab_index, False)
        self.tabs.setCurrentIndex(0)
        self.setVisible(False)
