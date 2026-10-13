"""Главное окно: menu bar + вкладки + статус-бар.

МЕНЮ СОДЕРЖИТ ТОЛЬКО РАБОЧИЕ ПУНКТЫ.
Dead menu items хуже, чем их отсутствие — пункты под нерабочие фичи
не добавляем, пока под ними нет кода.

=============================================================================
 КАРТА ВСТАВОК — где что дописывать
=============================================================================

 Импорты сверху:          добавляй новые view/worker/widget по мере появления.
                          Порядок: сначала PySide6, потом pcap_triage_gui.

 _build_menubar:          добавляй меню и action'ы. Если action ведёт на
                          нереализованное — enabled=False, не скрывай.

 _build_tabs:             для каждой новой вкладки замени _placeholder_page
                          на реальный *View() и подключи сигналы.

 _build_statusbar:        permanent widgets (версия, TI) — справа,
                          обычные (статус, файл) — слева.

 handlers:                слоты окна. Сгруппированы: меню-действия, потом
                          подписчики сигналов от views.

 keyPressEvent:           глобальные клавиши окна. Esc живёт тут, а не в
                          QAction — чтобы модалки ловили Esc первыми.

=============================================================================
"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QMessageBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# >>> ИМПОРТЫ VIEWS/WORKERS/WIDGETS <<<
# По мере появления новых вкладок добавляй сюда их view-классы.
from pcap_triage_gui.views.run_view import RunView
# from pcap_triage_gui.views.enrich_view import EnrichView        # шаг 13
# from pcap_triage_gui.views.settings_view import SettingsView    # шаг 12
# from pcap_triage_gui.views.history_view import HistoryView      # шаг 13
# from pcap_triage_gui.views.roadmap_view import RoadmapView      # шаг 13
# >>> /ИМПОРТЫ <<<


TAB_TITLES = ("Прогон", "Обогащение", "Настройки", "История", "Развитие")
APP_VERSION = "0.7.0"


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"pcap-triage v{APP_VERSION}")
        self.resize(1440, 900)

        self._build_menubar()
        self._build_tabs()
        self._build_statusbar()

    # =========================================================================
    # MENU BAR
    # =========================================================================

    def _act(self, text, shortcut=None, slot=None, enabled=True) -> QAction:
        """Фабрика QAction: меньше boilerplate в каждом меню."""
        a = QAction(text, self)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if slot:
            a.triggered.connect(slot)
        a.setEnabled(enabled)
        return a

    def _build_menubar(self) -> None:
        mb = self.menuBar()
        mb.setNativeMenuBar(False)  # хотим единый вид, а не нативный macOS-стиль

        self._menu_file(mb)
        self._menu_run(mb)
        # >>> ДОБАВИТЬ МЕНЮ <<<
        # Шаг 12:  self._menu_settings(mb)
        # Шаг 13:  self._menu_enrich(mb)
        #          self._menu_history(mb)
        #          self._menu_roadmap(mb)
        # >>> /ДОБАВИТЬ МЕНЮ <<<
        self._menu_view(mb)
        self._menu_help(mb)

    def _menu_file(self, mb) -> None:
        m = mb.addMenu("Файл")
        m.addAction(self._act("Открыть pcap…", "Ctrl+O", self._on_open_pcap))
        m.addSeparator()
        m.addAction(self._act("Выход", "Ctrl+Q", self.close))

        # >>> ФАЙЛ: ЭКСПОРТ <<<
        # Шаг 14: подменю «Экспорт» (JSON / MD / conn.log).
        #         enabled=True появится вместе с обёрткой над reporters.
        # >>> /ФАЙЛ: ЭКСПОРТ <<<

    def _menu_run(self, mb) -> None:
        m = mb.addMenu("Прогон")
        # F5 включён с шага 9 — вызывает reanalyze() на текущем файле.
        self._act_analyze = self._act(
            "Анализировать", "F5", self._on_analyze, enabled=True,
        )
        # Ctrl+F5 включится после шага 12 (settings_view).
        self._act_analyze_cfg = self._act(
            "Анализировать с настройками…", "Ctrl+F5",
            self._on_analyze_with_config, enabled=False,
        )
        # Остановить включится после шага 8-stop (worker.stop).
        self._act_stop = self._act(
            "Остановить", slot=self._on_stop, enabled=False,
        )
        m.addAction(self._act_analyze)
        m.addAction(self._act_analyze_cfg)
        m.addSeparator()
        m.addAction(self._act_stop)

        # >>> ПРОГОН: ПРЕСЕТЫ <<<
        # Пресеты детекторов появятся, когда Config научится принимать
        # подмножество детекторов (правка ядра — вне текущей сессии).
        # >>> /ПРОГОН: ПРЕСЕТЫ <<<

    def _menu_settings(self, mb) -> None:
        """Шаг 12. Пока в _build_menubar не вызывается."""
        m = mb.addMenu("Настройки")
        m.addAction(self._act("Открыть настройки…", "Ctrl+,",
                              self._on_open_settings, enabled=False))

    def _menu_view(self, mb) -> None:
        m = mb.addMenu("Вид")
        # Навигация по вкладкам — работает сразу.
        for i, title in enumerate(TAB_TITLES):
            m.addAction(self._act(title, slot=lambda i=i: self.tabs.setCurrentIndex(i)))
        m.addSeparator()
        m.addAction(self._act("Полноэкранный режим", "F11", self._toggle_fullscreen))

    def _menu_help(self, mb) -> None:
        m = mb.addMenu("Помощь")
        m.addAction(self._act("О программе", slot=self._on_about))
        m.addAction(self._act("Горячие клавиши", slot=self._on_hotkeys))

    # =========================================================================
    # TABS
    # =========================================================================

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # --- Реальные вкладки (по мере готовности) ---
        # Шаг 9: Прогон
        self.run_view = RunView()
        self.run_view.analysis_started.connect(self._on_analysis_started)
        self.run_view.analysis_finished.connect(self._on_analysis_finished)
        self.tabs.addTab(self.run_view, TAB_TITLES[0])

        # >>> ДОБАВИТЬ ВКЛАДКИ <<<
        # Шаг 12: self.settings_view = SettingsView()
        #         self.tabs.insertTab(2, self.settings_view, TAB_TITLES[2])
        # Шаг 13: EnrichView / HistoryView / RoadmapView
        # >>> /ДОБАВИТЬ ВКЛАДКИ <<<

        # --- Заглушки вместо ещё не готовых вкладок ---
        # Индекс 0 занят RunView, остальные — пока заглушки.
        # При появлении реального view — убирай соответствующий title
        # из этого цикла.
        self.tabs.addTab(self._placeholder_page(TAB_TITLES[1]), TAB_TITLES[1])
        self.tabs.addTab(self._placeholder_page(TAB_TITLES[2]), TAB_TITLES[2])
        self.tabs.addTab(self._placeholder_page(TAB_TITLES[3]), TAB_TITLES[3])
        self.tabs.addTab(self._placeholder_page(TAB_TITLES[4]), TAB_TITLES[4])

        self.setCentralWidget(self.tabs)

    def _placeholder_page(self, title: str) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        lbl = QLabel(f"«{title}» — будет реализовано позже.")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setObjectName("muted")
        layout.addWidget(lbl)
        return w

    # =========================================================================
    # STATUS BAR
    # =========================================================================

    def _build_statusbar(self) -> None:
        sb = self.statusBar()

        # Слева: статус + файл.
        self._status_text = QLabel("Готов")
        self._status_file = QLabel("—")
        self._status_file.setObjectName("muted")
        sb.addWidget(self._status_text)
        sb.addWidget(QLabel("  Файл:"))
        sb.addWidget(self._status_file)

        # Справа (permanent): версия, потом TI-провайдеры.
        sb.addPermanentWidget(QLabel(f"Версия: {APP_VERSION}"))

        # >>> СТАТУС-БАР: TI <<<
        # Шаг 13: sb.addPermanentWidget(QLabel("TI: AbuseIPDB ✓ · Shodan ✓"))
        # >>> /СТАТУС-БАР: TI <<<

    # =========================================================================
    # HANDLERS — действия меню
    # =========================================================================

    def _on_open_pcap(self) -> None:
        # try/except временно: Qt молча глотает ошибки в слотах, и мы
        # не видим причину. Покажем её в QMessageBox и в консоль.
        try:
            self.tabs.setCurrentIndex(0)
            self.run_view.open_file_dialog()
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Ошибка", f"{type(e).__name__}: {e}")

    def _on_analyze(self) -> None:
        self.run_view.reanalyze()

    def _on_analyze_with_config(self) -> None:
        self.statusBar().showMessage("Анализ с настройками — после шага 12", 3000)

    def _on_stop(self) -> None:
        self.statusBar().showMessage("Остановка — на шаге 8", 3000)

    def _on_open_settings(self) -> None:
        self.statusBar().showMessage("Настройки — на шаге 12", 3000)

    def _on_about(self) -> None:
        QMessageBox.about(
            self,
            "О программе",
            f"<b>pcap-triage v{APP_VERSION}</b><br><br>"
            "Оффлайн-триаж pcap.<br>"
            "17 детекторов · 8 экстракторов · 7 правил ContradictionDetector.",
        )

    def _on_hotkeys(self) -> None:
        QMessageBox.information(
            self,
            "Горячие клавиши",
            "Ctrl+O — открыть pcap\n"
            "F5 — анализ\n"
            "F11 — полноэкранный режим",
        )

    # =========================================================================
    # HANDLERS — подписчики сигналов от views
    # =========================================================================

    # >>> СИГНАЛЫ ОТ RunView <<<
    def _on_analysis_started(self, path: str) -> None:
        self._status_text.setText("Анализ…")
        self._status_file.setText(path)

    def _on_analysis_finished(self, report: object) -> None:
        s = report.get("summary", {}) if isinstance(report, dict) else {}
        self._status_text.setText(
            f"Готово · {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий"
        )
    # >>> /СИГНАЛЫ ОТ RunView <<<

    # >>> СИГНАЛЫ ОТ ДРУГИХ VIEWS <<<
    # Шаг 12–13: слоты для settings_view / enrich_view / history_view.
    # >>> /СИГНАЛЫ ОТ ДРУГИХ VIEWS <<<

    # =========================================================================
    # MISC
    # =========================================================================

    def _toggle_fullscreen(self) -> None:
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def keyPressEvent(self, event) -> None:
        # Esc держим в окне, а не в QAction — чтобы в будущем модалки
        # ловили Esc первыми и не закрывали окно.
        if event.key() == Qt.Key.Key_Escape:
            self.statusBar().showMessage("Остановка анализа — на шаге 8", 2000)
            return
        super().keyPressEvent(event)