"""Главное окно: menu bar + вкладки + статус-бар.

МЕНЮ СОДЕРЖИТ ТОЛЬКО РАБОЧИЕ ПУНКТЫ.
Dead menu items хуже, чем их отсутствие — пункты под нерабочие фичи
не добавляем, пока под ними нет кода.

=============================================================================
 КАРТА ВСТАВОК — где что дописывать
=============================================================================

 Импорты сверху:          PySide6 → paradox_gui → stdlib.
                          Порядок внутри блока не важен, главное — три группы.

 _build_menubar:          центральный метод. Каждое меню — отдельный
                          метод _menu_xxx, вызывается отсюда.
                          Маркер >>> ДОБАВИТЬ МЕНЮ <<< — точка расширения.

 _menu_file:              подменю «Экспорт» — маркер >>> ФАЙЛ: ЭКСПОРТ <<<.
                          Новые форматы (CSV, STIX) добавляются туда же.

 _build_tabs:             для каждой новой вкладки замени
                          _placeholder_page на реальный *View()
                          и подключи сигналы. Маркер >>> ДОБАВИТЬ ВКЛАДКИ <<<.

 _build_statusbar:        permanent widgets (версия, TI) — справа,
                          обычные (статус, файл) — слева.

 HANDLERS — действия меню: слоты от QAction'ов.
 HANDLERS — подписчики:    слоты от сигналов views.
 EXPORT:                   всё, что связано с сохранением отчётов.

 keyPressEvent:           глобальные клавиши окна. Esc живёт тут, а не
                          в QAction — чтобы модалки ловили Esc первыми.
=============================================================================
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from paradox_gui import __version__ as APP_VERSION
from paradox_gui.i18n import DEFAULT_LANGUAGE, set_language, tr
from paradox_gui.views.diff_view import DiffView
from paradox_gui.views.enrich_view import EnrichView
from paradox_gui.views.export_view import ExportView
from paradox_gui.views.history_view import HistoryView
from paradox_gui.views.ipv6_view import IPv6View
from paradox_gui.views.payload_view import PayloadView
from paradox_gui.views.run_view import RunView
from paradox_gui.views.settings_view import SettingsView
from paradox_gui.views.timeline_view import TimelineView
from paradox_gui.window.actions import ActionsMixin
from paradox_gui.window.export import ExportMixin
from paradox_gui.window.menus import MenusMixin
from paradox_gui.window.shortcuts import ShortcutsMixin


class ClickableLabel(QLabel):
    from PySide6.QtCore import Signal
    clicked = Signal()
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


# Ключи вкладок в порядке добавления. Держим их отдельно: по ним
# tools/docs_inventory.py печатает состав GUI без запуска окна.
TAB_TITLE_KEYS = (
    "tab.run",
    "tab.history",
    "tab.payload",
    "tab.enrich",
    "tab.settings",
    "tab.ipv6",
    "tab.timeline",
    "tab.export",
    "tab.diff",
)
TAB_TITLES = tuple(tr(key) for key in TAB_TITLE_KEYS)


class MainWindow(
    MenusMixin,
    ActionsMixin,
    ExportMixin,
    ShortcutsMixin,
    QMainWindow,
):
    def __init__(self) -> None:
        super().__init__()
        # Язык читаем ДО setWindowTitle/_build_menubar: они вызывают tr().
        from paradox_gui.settings_store import SettingsStore as _SS
        self._settings_store = _SS()
        _saved_lang = self._settings_store.load().get(
            "language", DEFAULT_LANGUAGE,
        )
        set_language(_saved_lang)
        self.setWindowTitle(tr("app.title", version=APP_VERSION))
        self.resize(1440, 900)
        self._apply_dark_titlebar()

        # Standalone QMenuBar (не self.menuBar()): кладётся в HBox
        # рядом с QTabBar, поэтому QMainWindow не управляет им.
        self._topmenu = QMenuBar(self)
        self._build_menubar()
        self._build_tabs()
        self._build_statusbar()


    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.run_view = RunView(store=self._settings_store)
        self.settings_view = SettingsView(store=self._settings_store)
        self.enrich_view = EnrichView()
        self.history_view = HistoryView()
        self.payload_view = PayloadView()
        self.ipv6_view = IPv6View()
        self.timeline_view = TimelineView()
        self.export_view = ExportView()

        self.run_view.analysis_started.connect(self._on_analysis_started)
        self.run_view.analysis_finished.connect(self._on_analysis_finished)
        self.run_view.analysis_failed.connect(self._on_analysis_failed)
        self.run_view.analysis_cancelled.connect(self._on_analysis_cancelled)
        # Новый прогон — старые выдержки уже не про этот отчёт.
        self.run_view.analysis_started.connect(self.payload_view.clear)

        self.settings_view.thresholds_applied.connect(
            self.run_view.set_config_overrides
        )
        self.settings_view.config_applied.connect(
            self.run_view.set_config_overrides
        )
        self.settings_view.detectors_applied.connect(
            self.run_view.set_disabled_detectors
        )
        self.settings_view.contradictions_applied.connect(
            self.run_view.set_disabled_contradictions
        )
        self.settings_view.config_applied.connect(
            self.enrich_view.set_config_overrides
        )

        self.enrich_view.enrichment_finished.connect(
            self._on_enrichment_finished
        )

        # Сравнение из Истории
        self.history_view.compare_requested.connect(self._on_compare_history)

        self.tabs.addTab(self.run_view, tr("tab.run"))
        self.tabs.addTab(self.history_view, tr("tab.history"))
        self.tabs.addTab(self.payload_view, tr("tab.payload"))
        self.tabs.addTab(self.enrich_view, tr("tab.enrich"))
        self.tabs.addTab(self.settings_view, tr("tab.settings"))
        self.tabs.addTab(self.ipv6_view, tr("tab.ipv6"))
        self.tabs.addTab(self.timeline_view, tr("tab.timeline"))
        self.tabs.addTab(self.export_view, tr("tab.export"))
        self.diff_view = DiffView()
        self.tabs.addTab(self.diff_view, tr("tab.diff"))

        # Шапка: логотип + меню
        try:
            from paradox_gui.logo import get_app_icon, render_logo
            self.setWindowIcon(get_app_icon())
            _logo = ClickableLabel()
            _logo.setPixmap(render_logo(24))
            _logo.setFixedSize(24, 24)
            _logo.setCursor(Qt.CursorShape.PointingHandCursor)
            _logo.setToolTip(tr("dialog.about.title"))
            _logo.clicked.connect(self._on_about)
        except Exception:
            _logo = None

        header = QWidget()
        header.setObjectName("topbar")
        header_h = QHBoxLayout(header)
        header_h.setContentsMargins(10, 4, 4, 0)
        header_h.setSpacing(6)
        if _logo is not None:
            header_h.addWidget(_logo)
        header_h.addWidget(self._topmenu, stretch=1)

        container = QWidget()
        vbox = QVBoxLayout(container)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(header)
        vbox.addWidget(self.tabs, stretch=1)
        self.setCentralWidget(container)


    def _build_statusbar(self) -> None:
        sb = self.statusBar()

        self._status_text = QLabel(tr("status.ready"))
        self._status_file = QLabel("—")
        self._status_file.setObjectName("muted")
        sb.addWidget(self._status_text)
        sb.addWidget(QLabel(tr("status.file")))
        sb.addWidget(self._status_file)

        self._version_lbl = ClickableLabel(f"v{APP_VERSION} · © v314xm")
        self._version_lbl.setObjectName("statusVersion")
        self._version_lbl.setCursor(Qt.CursorShape.PointingHandCursor)
        self._version_lbl.setToolTip(tr("dialog.about.title"))
        self._version_lbl.clicked.connect(self._on_about)
        sb.addPermanentWidget(self._version_lbl)


    def closeEvent(self, event) -> None:
        """Не дать QThread умереть вместе с окном.

        Закрытие во время анализа уничтожает AnalysisWorker, пока
        run() внутри парсера — Qt аварийно завершает процесс без
        traceback. Тот же риск у EnrichmentWorker.
        """
        busy = self.run_view.is_busy() or self.enrich_view.is_busy()
        if busy:
            answer = QMessageBox.question(
                self,
                tr("dialog.busy.title"),
                tr("dialog.busy.body"),
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

            if self.run_view.is_busy():
                self.run_view.stop_analysis()

            # Ждём оба потока: Qt уничтожает QThread при закрытии
            # окна, а живой поток роняет процесс.
            stopped = self.run_view.wait_for_finish(10000)
            stopped = self.enrich_view.wait_for_finish(10000) and stopped
            if not stopped:
                QMessageBox.warning(
                    self,
                    tr("error.stop_failed.title"),
                    tr("error.stop_failed.body"),
                )
                event.ignore()
                return

        # Окно «Код инжекта» живёт независимо от главного, но вместе
        # с приложением: иначе после закрытия остаётся осиротевшее окно.
        payload_window = getattr(self, "_payload_window", None)
        if payload_window is not None:
            payload_window.close()

        super().closeEvent(event)
