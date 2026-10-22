"""Таблица findings из report["findings"].

Колонки: Тип · Значение · Conf · MITRE · First seen.
Severity не показываем — в ядре её нет, а маппинг type→severity
в GUI был бы второй правдой, которая разойдётся с ядром.
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSizePolicy,
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


class _ConfItem(QTableWidgetItem):
    """QTableWidgetItem с числовым сравнением для сортировки по confidence.

    Стандартный QTableWidgetItem.sortItems() сравнивает DisplayRole —
    если туда положена строка "0.85", сортировка лексикографическая.
    Кладём float в отдельный атрибут и переопределяем __lt__.
    """

    def __init__(self, conf: float) -> None:
        super().__init__(f"{conf:.2f}")
        self._conf = conf

    def __lt__(self, other) -> bool:
        if isinstance(other, _ConfItem):
            return self._conf < other._conf
        return super().__lt__(other)


class FindingsTable(QFrame):
    # object, а не dict — стабильнее в PySide6.
    row_activated = Signal(object)
    host_story_requested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Expanding,
        )
        self.setMinimumHeight(280)  # ← ЭТА СТРОКА
        self._findings_cache: list[dict] = []

        # Дебаунсер для поиска (защита от лагов при вводе)
        from PySide6.QtCore import QTimer
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(200)
        self._search_timer.timeout.connect(self._apply_filters)

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
        layout.addLayout(self._build_filter_bar())

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
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
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        layout.addWidget(self._table)

    # ---------- публичный API ----------

    def set_findings(self, findings: list[dict]) -> None:
        self._findings_cache = list(findings)
        self._table.setSortingEnabled(False)  # на время заполнения — иначе пляшет
        self._table.setRowCount(0)

        if not findings:
            self._rebuild_type_filter()
            self._count_label.setText("")
            self.setVisible(False)
            return

        for f in findings:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._fill_row(row, f)

        self._rebuild_type_filter()
        self._table.setSortingEnabled(True)
        # Сортировка по Conf desc — самый сильный сигнал сверху.
        self._table.sortItems(2, Qt.SortOrder.DescendingOrder)
        self._apply_filters()
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
        conf_item = (
            _ConfItem(float(conf)) if isinstance(conf, (int, float))
            else QTableWidgetItem("")
        )

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

    def _on_context_menu(self, pos) -> None:
        item = self._table.itemAt(pos)
        if item is None:
            return

        row = item.row()
        type_item = self._table.item(row, 0)
        if type_item is None:
            return

        f = type_item.data(_ROW_DATA_ROLE)
        if not isinstance(f, dict):
            return

        menu = QMenu(self)
        src = f.get("src_ip")
        dst = f.get("dst_ip")

        if src:
            act_src = menu.addAction(f"История хоста (src): {src}")
            act_src.triggered.connect(lambda: self.host_story_requested.emit(src))
        if dst:
            act_dst = menu.addAction(f"История хоста (dst): {dst}")
            act_dst.triggered.connect(lambda: self.host_story_requested.emit(dst))

        if src or dst:
            menu.exec(self._table.viewport().mapToGlobal(pos))

    def _on_double_click(self, row: int, _col: int) -> None:
        # Двойной клик, а не одиночный — чтобы выделение не открывало
        # модалку случайно. Одиночный клик оставляем для выделения.
        item = self._table.item(row, 0)
        if item is None:
            return
        data = item.data(_ROW_DATA_ROLE)
        if isinstance(data, dict):
            self.row_activated.emit(data)

    # =========================================================================
    # ФИЛЬТРЫ
    # =========================================================================

    def _build_filter_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Поиск по value / типу / MITRE…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(lambda: self._search_timer.start())
        bar.addWidget(self._search, stretch=1)

        self._type_filter = QComboBox()
        self._type_filter.setMinimumWidth(160)
        self._type_filter.currentIndexChanged.connect(self._apply_filters)
        bar.addWidget(self._type_filter)

        self._conf_filter = QComboBox()
        self._conf_filter.setMinimumWidth(100)
        self._conf_filter.addItem("Conf: все", None)
        self._conf_filter.addItem("Conf ≥ 0.5", 0.5)
        self._conf_filter.addItem("Conf ≥ 0.7", 0.7)
        self._conf_filter.addItem("Conf ≥ 0.85", 0.85)
        self._conf_filter.currentIndexChanged.connect(self._apply_filters)
        bar.addWidget(self._conf_filter)

        reset = QPushButton("✕")
        reset.setToolTip("Сбросить фильтры")
        reset.setFixedWidth(32)
        reset.clicked.connect(self._reset_filters)
        bar.addWidget(reset)

        return bar

    def _reset_filters(self) -> None:
        self._search.blockSignals(True)
        self._type_filter.blockSignals(True)
        self._conf_filter.blockSignals(True)
        self._search.clear()
        self._type_filter.setCurrentIndex(0)
        self._conf_filter.setCurrentIndex(0)
        self._search.blockSignals(False)
        self._type_filter.blockSignals(False)
        self._conf_filter.blockSignals(False)
        self._search_timer.stop()
        self._apply_filters()

    def _rebuild_type_filter(self) -> None:
        current = self._type_filter.currentData()
        self._type_filter.blockSignals(True)
        self._type_filter.clear()
        self._type_filter.addItem("Все типы", None)
        types = sorted({str(f.get("type", "")) for f in self._findings_cache if f.get("type")})
        for t in types:
            self._type_filter.addItem(t, t)
        # восстановить выбор, если тип ещё присутствует
        idx = self._type_filter.findData(current) if current else 0
        self._type_filter.setCurrentIndex(max(0, idx))
        self._type_filter.blockSignals(False)

    @staticmethod
    def _mitre_text(f: dict) -> str:
        m = f.get("mitre_techniques") or ()
        if isinstance(m, str):
            return m
        if isinstance(m, (list, tuple)):
            return ", ".join(map(str, m))
        return str(m)

    def _apply_filters(self) -> None:
        text = self._search.text().strip().lower()
        type_sel = self._type_filter.currentData()
        conf_min = self._conf_filter.currentData()

        total = self._table.rowCount()
        shown = 0
        for row in range(total):
            item = self._table.item(row, 0)
            f = item.data(_ROW_DATA_ROLE) if item is not None else None
            if not isinstance(f, dict):
                self._table.setRowHidden(row, True)
                continue

            if type_sel is not None and str(f.get("type", "")) != str(type_sel):
                self._table.setRowHidden(row, True)
                continue

            if conf_min is not None:
                conf = f.get("confidence")
                if not isinstance(conf, (int, float)) or float(conf) < float(conf_min):
                    self._table.setRowHidden(row, True)
                    continue

            if text:
                haystack = " ".join((
                    str(f.get("type", "")),
                    str(f.get("value", "")),
                    self._mitre_text(f),
                )).lower()
                if text not in haystack:
                    self._table.setRowHidden(row, True)
                    continue

            self._table.setRowHidden(row, False)
            shown += 1

        if shown == total:
            self._count_label.setText(f"({total})")
        else:
            self._count_label.setText(f"({shown} из {total})")

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
