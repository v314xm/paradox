"""Таблица findings из report["findings"].

Колонки: Тип · Значение · Conf · MITRE · First seen.
Severity не показываем — в ядре её нет, а маппинг type→severity
в GUI был бы второй правдой, которая разойдётся с ядром.
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSizePolicy,          # ← добавить
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)


# Колонки: (заголовок, ширина по умолчанию в пикселях, растягивать?)
_COLUMNS = (
    ("Тип",         180, False),
    ("Значение",    0,   True),    # тянется
    ("Conf",        70,  False),
    ("MITRE",       110, False),
    ("First seen",  140, False),
)

# Роль для хранения исходного dict'а finding'а в строке таблицы.
_ROW_DATA_ROLE = Qt.ItemDataRole.UserRole + 1


class FindingsTable(QFrame):
    # object, а не dict — стабильнее в PySide6.
    row_activated = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Expanding,
        )
        self.setMinimumHeight(280)  # ← ЭТА СТРОКА
        self._build_ui()
        self.setVisible(False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel("Findings")
        title.setObjectName("h1")
        self._count_label = QLabel("")
        self._count_label.setObjectName("muted")
        header.addWidget(title)
        header.addWidget(self._count_label)
        header.addStretch(1)
        layout.addLayout(header)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self._table.setHorizontalHeaderLabels([c[0] for c in _COLUMNS])
        self._table.setHorizontalHeaderLabels([c[0] for c in _COLUMNS])
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)

        hh = self._table.horizontalHeader()
        for i, (_, width, stretch) in enumerate(_COLUMNS):
            if stretch:
                hh.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            else:
                hh.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
                self._table.setColumnWidth(i, width)

        self._table.cellDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

    # ---------- публичный API ----------

    def set_findings(self, findings: list[dict]) -> None:
        self._table.setSortingEnabled(False)  # на время заполнения — иначе пляшет
        self._table.setRowCount(0)

        if not findings:
            self.setVisible(False)
            return

        self._count_label.setText(f"({len(findings)})")

        for f in findings:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._fill_row(row, f)

        self._table.setSortingEnabled(True)
        # Сортировка по Conf desc — самый сильный сигнал сверху.
        self._table.sortItems(2, Qt.SortOrder.DescendingOrder)
        self.setVisible(True)

    def clear(self) -> None:
        self._table.setRowCount(0)
        self._count_label.setText("")
        self.setVisible(False)

    # ---------- внутреннее ----------

    def _fill_row(self, row: int, f: dict) -> None:
        type_item = QTableWidgetItem(str(f.get("type", "?")))
        type_item.setData(_ROW_DATA_ROLE, f)

        value_item = QTableWidgetItem(str(f.get("value", "")))

        conf = f.get("confidence")
        conf_item = QTableWidgetItem()
        if isinstance(conf, (int, float)):
            # Сортировка должна идти по числу, а показывать — 2 знака.
            conf_item.setData(Qt.ItemDataRole.DisplayRole, float(conf))
            conf_item.setText(f"{conf:.2f}")
        else:
            conf_item.setText("")

        mitre = f.get("mitre_techniques") or ()
        if isinstance(mitre, str):
            mitre = (mitre,)
        mitre_item = QTableWidgetItem(", ".join(mitre))

        ts = f.get("first_seen")
        ts_item = QTableWidgetItem(self._format_ts(ts))
        if isinstance(ts, (int, float)):
            ts_item.setData(Qt.ItemDataRole.UserRole, float(ts))

        for col, item in enumerate(
            (type_item, value_item, conf_item, mitre_item, ts_item)
        ):
            self._table.setItem(row, col, item)

    def _on_double_click(self, row: int, _col: int) -> None:
        # Двойной клик, а не одиночный — чтобы выделение не открывало
        # модалку случайно. Одиночный клик оставляем для выделения.
        item = self._table.item(row, 0)
        if item is None:
            return
        data = item.data(_ROW_DATA_ROLE)
        if isinstance(data, dict):
            self.row_activated.emit(data)

    @staticmethod
    def _format_ts(ts) -> str:
        if ts is None:
            return ""
        if isinstance(ts, (int, float)):
            from datetime import datetime
            try:
                return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, ValueError):
                return f"{ts:.1f}"
        return str(ts)