"""QuickCheckWindow — немодальное окно быстрой проверки IOC."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from paradox.integrations.cache import EnrichmentCache
from paradox.integrations.registry import REGISTRY
from paradox_gui.i18n import tr
from paradox_gui.ioc_utils import detect_ioc_type, provider_link
from paradox_gui.widgets.provider_card import ProviderCard
from paradox_gui.workers.quick_check_worker import QuickCheckWorker

_AUTO_KEY = "quick_check.auto"
_TYPES = ("ip", "domain", "url", "hash")


class QuickCheckWindow(QWidget):
    """Отдельное окно (top-level), работает параллельно с главным.

    Открывается из меню Help. Не модально: можно смотреть отчёт и
    параллельно проверять IOC.
    """

    def __init__(self, config, parent=None) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle("Быстрая проверка IOC — Paradox")
        self.resize(900, 760)

        self._config = config
        # Ключи уже в os.environ — их прокинул SettingsView
        # при старте GUI, либо они заданы в системе. Провайдеры
        # читают os.environ в __init__.

        self._worker: QuickCheckWorker | None = None
        self._cache: EnrichmentCache | None = None
        self._report: dict | None = None

        self._build_ui()
        self._wire_shortcuts()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(10)

        title = QLabel(tr("quick_check.title"))
        title.setObjectName("h1")
        outer.addWidget(title)

        subtitle = QLabel(tr("quick_check.subtitle"))
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)

        # --- input row ---
        input_row = QHBoxLayout()
        input_row.setSpacing(8)

        self._type_combo = QComboBox()
        self._type_combo.addItem(tr(_AUTO_KEY))
        for t in _TYPES:
            self._type_combo.addItem(t)
        self._type_combo.setFixedWidth(110)
        input_row.addWidget(self._type_combo)

        self._ioc_input = QLineEdit()
        self._ioc_input.setPlaceholderText(tr("quick_check.input_placeholder"))
        self._ioc_input.setMinimumHeight(30)
        self._ioc_input.returnPressed.connect(self._on_check)
        self._ioc_input.textChanged.connect(self._on_input_changed)
        input_row.addWidget(self._ioc_input, stretch=1)

        self._check_btn = QPushButton(tr("quick_check.check_button"))
        self._check_btn.setObjectName("primary")
        self._check_btn.setMinimumHeight(30)
        self._check_btn.setMinimumWidth(140)
        self._check_btn.clicked.connect(self._on_check)
        input_row.addWidget(self._check_btn)

        outer.addLayout(input_row)

        # --- IOC из последнего прогона ---
        from_row = QHBoxLayout()
        from_row.setSpacing(8)
        from_lbl = QLabel(tr("quick_check.from_last_run"))
        from_lbl.setObjectName("muted")
        from_row.addWidget(from_lbl)

        self._ioc_combo = QComboBox()
        self._ioc_combo.setMinimumWidth(420)
        self._ioc_combo.addItem(tr("quick_check.no_data"))
        self._ioc_combo.setEnabled(False)
        self._ioc_combo.currentIndexChanged.connect(
            self._on_ioc_combo_changed,
        )
        from_row.addWidget(self._ioc_combo, stretch=1)
        from_row.addStretch(1)
        outer.addLayout(from_row)

        # --- detected type hint ---
        self._type_hint = QLabel("")
        self._type_hint.setObjectName("muted")
        outer.addWidget(self._type_hint)

        # --- progress ---
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setTextVisible(False)
        self._progress.setVisible(False)
        outer.addWidget(self._progress)

        # --- results scroll ---
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self._results_host = QWidget()
        self._results_layout = QVBoxLayout(self._results_host)
        self._results_layout.setContentsMargins(0, 0, 0, 0)
        self._results_layout.setSpacing(8)
        self._results_layout.addStretch(1)
        scroll.setWidget(self._results_host)
        outer.addWidget(scroll, stretch=1)

        self._status = QLabel("")
        self._status.setObjectName("muted")
        outer.addWidget(self._status)

    def _wire_shortcuts(self) -> None:
        from PySide6.QtCore import Qt as _Qt
        sc = QShortcut(QKeySequence("Ctrl+Return"), self)
        sc.setContext(_Qt.ShortcutContext.WidgetWithChildrenShortcut)
        sc.activated.connect(self._on_check)
        self._sc = sc

    # ------------------------------------------------------------- handlers

    def set_report(self, report: dict | None) -> None:
        """Обновить список IOC из отчёта последнего прогона."""
        self._report = report
        self._refresh_ioc_combo()

    def _refresh_ioc_combo(self) -> None:
        self._ioc_combo.blockSignals(True)
        self._ioc_combo.clear()
        self._ioc_combo.addItem(tr("quick_check.select_ioc"), userData=None)

        if not self._report or not isinstance(self._report, dict):
            self._ioc_combo.addItem(tr("quick_check.no_run"))
            self._ioc_combo.setEnabled(False)
            self._ioc_combo.blockSignals(False)
            return

        try:
            from paradox.integrations.enricher import (
                collect_iocs_from_findings,
            )
            findings = self._report.get("findings", []) or []
            iocs = collect_iocs_from_findings(findings)
        except Exception:
            iocs = []

        if not iocs:
            self._ioc_combo.addItem(tr("quick_check.no_iocs"))
            self._ioc_combo.setEnabled(False)
            self._ioc_combo.blockSignals(False)
            return

        seen: set[tuple[str, str]] = set()
        for ioc_type, ioc in iocs:
            key = (ioc_type, str(ioc))
            if key in seen:
                continue
            seen.add(key)
            self._ioc_combo.addItem(
                f"{ioc_type:<8} {ioc}", userData=key,
            )

        self._ioc_combo.setEnabled(self._ioc_combo.count() > 1)
        self._ioc_combo.blockSignals(False)

    def _on_ioc_combo_changed(self, idx: int) -> None:
        data = self._ioc_combo.itemData(idx)
        if not data:
            return
        ioc_type, ioc = data
        self._ioc_input.setText(ioc)
        for i in range(self._type_combo.count()):
            if self._type_combo.itemText(i) == ioc_type:
                self._type_combo.setCurrentIndex(i)
                break

    def _on_input_changed(self, text: str) -> None:
        t = detect_ioc_type(text)
        if t:
            self._type_hint.setText(tr("quick_check.type_detected", type=t))
        elif text.strip():
            self._type_hint.setText(tr("quick_check.type_unknown"))
        else:
            self._type_hint.setText("")

    def _resolve_type(self) -> str | None:
        cur = self._type_combo.currentText()
        if cur != tr(_AUTO_KEY):
            return cur
        return detect_ioc_type(self._ioc_input.text())

    def _on_check(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return

        ioc = self._ioc_input.text().strip()
        if not ioc:
            return

        ioc_type = self._resolve_type()
        if ioc_type is None:
            QMessageBox.warning(
                self, tr("quick_check.warning_type"),
                tr("quick_check.warning_type_body"),
            )
            return

        # Подготовить провайдеров.
        enabled_names = set(self._config.enrichment_enabled_providers)
        providers = []
        for name, cls in REGISTRY.items():
            if name not in enabled_names:
                continue
            try:
                p = cls()
            except TypeError:
                p = cls(auth_key="")
            if not getattr(p, "enabled", True):
                continue
            if ioc_type not in getattr(p, "supports", ()):
                continue
            providers.append(p)

        if not providers:
            QMessageBox.information(
                self, tr("quick_check.no_providers"),
                tr("quick_check.no_providers_body", type=ioc_type),
            )
            return

        # Кэш: пересоздаём один раз.
        if self._cache is None:
            try:
                self._cache = EnrichmentCache(self._config.enrichment_cache_path)
            except Exception:
                self._cache = None

        self._clear_results()
        self._set_busy(True)
        self._status.setText(
            tr("quick_check.querying",
               count=len(providers), ioc=ioc, type=ioc_type)
        )

        self._worker = QuickCheckWorker(
            ioc, ioc_type, providers, self._cache, parent=self,
        )
        self._worker.done.connect(
            lambda results: self._on_done(results, ioc, ioc_type)
        )
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_thread_done)
        self._worker.start()

    def _on_done(self, results: dict, ioc: str, ioc_type: str) -> None:
        self._set_busy(False)
        if not results:
            self._status.setText(tr("quick_check.no_results"))
            return

        # Сортировка: сначала «плохие», потом warn, info, clean, empty, error.
        order = {"bad": 0, "warn": 1, "info": 2, "clean": 3, "empty": 4, "error": 5}
        from paradox_gui.widgets.provider_card import _verdict as _v

        def sort_key(item):
            name, res = item
            v = _v(name, res.data if res.ok else None,
                   None if res.ok else res.error)
            return (order.get(v, 10), name)

        for name, res in sorted(results.items(), key=sort_key):
            link = provider_link(name, ioc, ioc_type)
            card = ProviderCard(name, res, ioc, ioc_type, link, parent=self)
            self._results_layout.insertWidget(
                self._results_layout.count() - 1, card,
            )

        self._status.setText(
            tr("quick_check.done", count=len(results), ioc=ioc)
        )

    def _on_failed(self, msg: str) -> None:
        self._set_busy(False)
        self._status.setText(tr("quick_check.error", msg=msg))

    def _on_thread_done(self) -> None:
        w = self._worker
        if w is not None:
            w.wait(2000)
        self._worker = None

    def _set_busy(self, busy: bool) -> None:
        self._check_btn.setEnabled(not busy)
        self._ioc_input.setEnabled(not busy)
        self._type_combo.setEnabled(not busy)
        self._progress.setVisible(busy)

    def _clear_results(self) -> None:
        while self._results_layout.count() > 1:
            item = self._results_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
