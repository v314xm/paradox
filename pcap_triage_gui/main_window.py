"""Главное окно: menu bar + вкладки + статус-бар.

МЕНЮ СОДЕРЖИТ ТОЛЬКО РАБОЧИЕ ПУНКТЫ.
Dead menu items хуже, чем их отсутствие — пункты под нерабочие фичи
не добавляем, пока под ними нет кода.

=============================================================================
 КАРТА ВСТАВОК — где что дописывать
=============================================================================

 Импорты сверху:          PySide6 → pcap_triage_gui → stdlib.
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
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# >>> ИМПОРТЫ VIEWS <<<

from pcap_triage_gui.views.enrich_view import EnrichView        # >>> ОБОГАЩЕНИЕ <<<
# Шаг 13: from pcap_triage_gui.views.history_view import HistoryView
from pcap_triage_gui.views.run_view import RunView
from pcap_triage_gui.views.settings_view import SettingsView
from pcap_triage_gui.views.history_view import HistoryView
# >>> РАЗВИТИЕ <<<
from pcap_triage_gui.views.roadmap_view import RoadmapView # >>> ИСТОРИЯ <<<
# >>> /РАЗВИТИЕ <<<
# Шаг 13: from pcap_triage_gui.views.enrich_view import EnrichView
#         from pcap_triage_gui.views.history_view import HistoryView
# >>> /ИМПОРТЫ VIEWS <<<


TAB_TITLES = ("Прогон", "Обогащение", "Настройки", "История", "Развитие")
APP_VERSION = "0.7.0"


# Соответствие латиница → кириллица в ЙЦУКЕН-раскладке.
# Qt матчит shortcut по символу, а не по физической клавише:
# Ctrl+O в русской раскладке приходит как Ctrl+Щ.
_LATIN_TO_CYR = {
    "A": "Ф", "B": "И", "C": "С", "D": "В", "E": "У", "F": "А",
    "G": "П", "H": "Р", "I": "Ш", "J": "О", "K": "Л", "L": "Д",
    "M": "Ь", "N": "Т", "O": "Щ", "P": "З", "Q": "Й", "R": "К",
    "S": "Ы", "T": "Е", "U": "Г", "V": "М", "W": "Ц", "X": "Ч",
    "Y": "Н", "Z": "Я",
}


def _cyr_variant(seq: str) -> str | None:
    out, changed = [], False
    for ch in seq:
        up = ch.upper()
        if up in _LATIN_TO_CYR:
            cyr = _LATIN_TO_CYR[up]
            out.append(cyr if ch.isupper() else cyr.lower())
            changed = True
        else:
            out.append(ch)
    return "".join(out) if changed else None


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"pcap-triage v{APP_VERSION}")
        self.resize(1440, 900)

        self._build_menubar()
        self._build_tabs()
        self._build_statusbar()

    # =========================================================================
    # ФАБРИКИ
    # =========================================================================

    def _act(self, text, shortcut=None, slot=None, enabled=True) -> QAction:
        a = QAction(text, self)
        if shortcut:
            # Оба варианта шортката: латиница + кириллица. Иначе Ctrl+O
            # не работает в русской раскладке.
            variants = [QKeySequence(shortcut)]
            cyr = _cyr_variant(shortcut)
            if cyr:
                variants.append(QKeySequence(cyr))
            a.setShortcuts(variants)
        if slot:
            a.triggered.connect(slot)
        a.setEnabled(enabled)
        return a

    # =========================================================================
    # MENU BAR
    # =========================================================================

    def _build_menubar(self) -> None:
        mb = self.menuBar()
        mb.setNativeMenuBar(False)  # единый вид, а не нативный macOS-стиль

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
        self._menu_settings(mb)

    def _menu_settings(self, mb) -> None:
        m = mb.addMenu("Настройки")
        m.addAction(self._act(
            "Открыть настройки…", "Ctrl+,", self._on_open_settings, enabled=True,
        ))
    def _menu_file(self, mb) -> None:
        m = mb.addMenu("Файл")
        m.addAction(self._act("Открыть pcap…", "Ctrl+O", self._on_open_pcap))

        # >>> ФАЙЛ: ЭКСПОРТ <<<
        # Подменю «Экспорт». Пункты выключены до первого успешного
        # анализа — включаются в _on_analysis_finished.
        m.addSeparator()
        export = m.addMenu("Экспорт")
        self._act_export_json = self._act(
            "JSON-отчёт…", slot=self._on_export_json, enabled=False,
        )
        self._act_export_md = self._act(
            "Markdown-отчёт…", slot=self._on_export_md, enabled=False,
        )
        self._act_export_conn = self._act(
            "Flow report (conn.log)…", slot=self._on_export_conn, enabled=False,
        )
        export.addAction(self._act_export_json)
        export.addAction(self._act_export_md)
        export.addSeparator()
        export.addAction(self._act_export_conn)
        # >>> /ФАЙЛ: ЭКСПОРТ <<<

        m.addSeparator()
        m.addAction(self._act("Выход", "Ctrl+Q", self.close))

    def _menu_run(self, mb) -> None:
        m = mb.addMenu("Прогон")
        self._act_analyze = self._act(
            "Анализировать", "F5", self._on_analyze, enabled=True,
        )
        self._act_analyze_cfg = self._act(
            "Анализировать с настройками…", "Ctrl+F5",
            self._on_analyze_with_config, enabled=False,
        )
        # >>> ОСТАНОВКА <<<
        self._act_stop = self._act(
            "Остановить", "Esc", self._on_stop, enabled=False,
        )
        # >>> /ОСТАНОВКА <<<
        m.addAction(self._act_analyze)
        m.addAction(self._act_analyze_cfg)
        m.addSeparator()
        m.addAction(self._act_stop)

    def _menu_view(self, mb) -> None:
        m = mb.addMenu("Вид")
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

        # --- Прогон ---
        self.run_view = RunView()
        self.run_view.analysis_started.connect(self._on_analysis_started)
        self.run_view.analysis_finished.connect(self._on_analysis_finished)
        # >>> ОСТАНОВКА <<<
        self.run_view.analysis_failed.connect(self._on_analysis_failed)
        self.run_view.analysis_cancelled.connect(self._on_analysis_cancelled)
        # >>> /ОСТАНОВКА <<<
        self.tabs.addTab(self.run_view, TAB_TITLES[0])

        # --- Настройки ---
        # Создание и connect идут ПАРАМИ, в правильном порядке:
        # сначала объект, потом подписки.
        self.settings_view = SettingsView()
        self.settings_view.thresholds_applied.connect(
            self.run_view.set_config_overrides
        )
        # Brute force / Сеть / Производительность — тоже идут через
        # config_overrides, но своими ключами. run_view мерджит.
        self.settings_view.config_applied.connect(
            self.run_view.set_config_overrides
        )
        self.settings_view.detectors_applied.connect(
            self.run_view.set_disabled_detectors
        )
        self.settings_view.contradictions_applied.connect(
            self.run_view.set_disabled_contradictions
        )
        self.tabs.insertTab(2, self.settings_view, TAB_TITLES[2])

        # --- Обогащение ---
        # >>> ОБОГАЩЕНИЕ <<<
        # Заглушка заменена на реальную вкладку. Report приходит из
        # _on_analysis_finished. Ключи API читаются ядром из
        # os.environ — их выставляет секция Threat Intel в настройках.
        self.enrich_view = EnrichView()
        self.settings_view.config_applied.connect(
            self.enrich_view.set_config_overrides
        )
        # После обогащения запись в истории нужно перерисовать:
        # report мутирован in-place (evidence.enrichment), но
        # QTextBrowser сам про это не узнает.
        self.enrich_view.enrichment_finished.connect(
            self._on_enrichment_finished
        )
        self.tabs.insertTab(1, self.enrich_view, TAB_TITLES[1])
        # >>> /ОБОГАЩЕНИЕ <<<

        # --- История ---
        # >>> ИСТОРИЯ <<<
        # In-memory список прогонов. Наполняется из _on_analysis_finished.
        self.history_view = HistoryView()
        self.tabs.addTab(self.history_view, TAB_TITLES[3])
        # >>> /ИСТОРИЯ <<<

        # >>> РАЗВИТИЕ <<<
        # Вкладка «Развитие» — статический роадмап, индексов не касается.
        # Создаём после всех вставок и просто добавляем в конец (индекс 4).
        self.roadmap_view = RoadmapView()
        self.tabs.addTab(self.roadmap_view, TAB_TITLES[4])
        # >>> /РАЗВИТИЕ <<<

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

        self._status_text = QLabel("Готов")
        self._status_file = QLabel("—")
        self._status_file.setObjectName("muted")
        sb.addWidget(self._status_text)
        sb.addWidget(QLabel("  Файл:"))
        sb.addWidget(self._status_file)

        sb.addPermanentWidget(QLabel(f"Версия: {APP_VERSION}"))

        # >>> СТАТУС-БАР: TI <<<
        # Шаг 13: sb.addPermanentWidget(QLabel("TI: AbuseIPDB ✓ · Shodan ✓"))
        # >>> /СТАТУС-БАР: TI <<<

    # =========================================================================
    # HANDLERS — действия меню
    # =========================================================================

    def _on_open_pcap(self) -> None:
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
        # >>> ОСТАНОВКА <<<
        self.run_view.stop_analysis()
        # >>> /ОСТАНОВКА <<<

    def _on_open_settings(self) -> None:
        self.tabs.setCurrentWidget(self.settings_view)

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
        # >>> ОСТАНОВКА <<<
        self._act_stop.setEnabled(True)
        self._act_analyze.setEnabled(False)
        # >>> /ОСТАНОВКА <<<

    def _on_analysis_finished(self, report: object) -> None:
        s = report.get("summary", {}) if isinstance(report, dict) else {}
        self._status_text.setText(
            f"Готово · {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий"
        )
        # Есть что сохранять — включаем экспорт.
        for a in (self._act_export_json, self._act_export_md, self._act_export_conn):
            a.setEnabled(True)

        # >>> ИСТОРИЯ <<<
        if isinstance(report, dict) and hasattr(self, "history_view"):
            self.history_view.add_run(report)
        # >>> /ИСТОРИЯ <<<

        # >>> ОБОГАЩЕНИЕ <<<
        # Каждый новый прогон сбрасывает состояние вкладки «Обогащение»:
        # кнопка «Обогатить» снова активна, таблица очищена.
        if isinstance(report, dict) and hasattr(self, "enrich_view"):
            self.enrich_view.set_report(report)

        # >>> ОСТАНОВКА <<<
        self._act_stop.setEnabled(False)
        self._act_analyze.setEnabled(True)
        # >>> /ОСТАНОВКА <<<
        # >>> /ИСТОРИЯ <<<
    # >>> /СИГНАЛЫ ОТ RunView <<<
    # >>> ОСТАНОВКА <<<
    def _on_analysis_cancelled(self) -> None:
        self._status_text.setText("Остановлено пользователем")
        self._act_stop.setEnabled(False)
        self._act_analyze.setEnabled(True)
    # >>> /ОСТАНОВКА <<<
    # >>> СИГНАЛЫ ОТ ДРУГИХ VIEWS <<<
    # Шаг 12–13: слоты для settings_view / enrich_view / history_view.
    # >>> /СИГНАЛЫ ОТ ДРУГИХ VIEWS <<<

    # >>> ОСТАНОВКА <<<
    def _on_analysis_failed(self, msg: str) -> None:
        # Ошибку показывает RunView своим QMessageBox и toast.
        # Здесь только меню: даём пользователю снова нажать F5.
        self._act_stop.setEnabled(False)
        self._act_analyze.setEnabled(True)
    # >>> /ОСТАНОВКА <<<

    # =========================================================================
    # EXPORT
    # =========================================================================

    def _on_enrichment_finished(self) -> None:
        """После успешного обогащения — обновить текущую
        запись в «Истории».

        report в истории — тот же объект, что в run_view /
        enrich_view. Обогащение мутирует его in-place.
        QTextBrowser сам не перерисуется, поэтому дёргаем явно.
        """
        if hasattr(self, "history_view"):
            self.history_view.refresh_current()

    def _on_export_json(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить JSON-отчёт", self._default_export_name("json"),
            "JSON (*.json);;Все файлы (*)",
        )
        if not path:
            return
        try:
            # Пишем напрямую через json.dump — не зависим от имени
            # функции в ядре (write_json / save_json / ...).
            Path(path).write_text(
                json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True),
                encoding="utf-8",
            )
            self._status_text.setText(f"Сохранено: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка сохранения", str(e))

    def _on_export_md(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить Markdown-отчёт", self._default_export_name("md"),
            "Markdown (*.md);;Все файлы (*)",
        )
        if not path:
            return
        try:
            # render_markdown — из присланного markdown_reporter.py.
            from pcap_triage.reporters.markdown_reporter import render_markdown
            Path(path).write_text(render_markdown(report), encoding="utf-8")
            self._status_text.setText(f"Сохранено: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка сохранения", str(e))

    def _on_export_conn(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить flow report", self._default_export_name("log"),
            "Log (*.log);;Все файлы (*)",
        )
        if not path:
            return
        try:
            # report["flows"] — dict от build_flow_report. Ключ со списком
            # top-flow'ов может называться по-разному; пробуем варианты.
            flows = report.get("flows", {})
            rows = (
                flows.get("top_by_bytes")
                or flows.get("top")
                or flows.get("rows")
                or []
            )
            lines = []
            for r in rows:
                if isinstance(r, dict):
                    lines.append("\t".join(str(r.get(k, "")) for k in (
                        "first_seen", "proto",
                        "src_ip", "src_port", "dst_ip", "dst_port",
                        "bytes",
                    )))
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            self._status_text.setText(f"Сохранено: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка сохранения", str(e))

    def _default_export_name(self, ext: str) -> str:
        report = self.run_view.last_report() or {}
        pcap = report.get("provenance", {}).get("pcap_path", "")
        stem = Path(pcap).stem if pcap else "report"
        return f"{stem}.{ext}"

    # =========================================================================
    # MISC
    # =========================================================================

    def _toggle_fullscreen(self) -> None:
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            # >>> ОСТАНОВКА <<<
            # Esc приоритетнее меню: если идёт анализ — стоп, иначе
            # не делаем ничего (модалки ловят Esc раньше главного окна,
            # так что сюда попадаем только когда модалок нет).
            if self.run_view.is_busy():
                self.run_view.stop_analysis()
                return
            # >>> /ОСТАНОВКА <<<
            return
        super().keyPressEvent(event)