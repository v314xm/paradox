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
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# >>> /ИМПОРТЫ VIEWS <<<
from paradox_gui import __version__ as APP_VERSION
from paradox_gui.i18n import DEFAULT_LANGUAGE, set_language, tr
from paradox_gui.views.diff_view import DiffView
from paradox_gui.views.enrich_view import EnrichView
from paradox_gui.views.export_view import ExportView
from paradox_gui.views.history_view import HistoryView
from paradox_gui.views.ipv6_view import IPv6View

# >>> ИМПОРТЫ VIEWS <<<
from paradox_gui.views.run_view import RunView
from paradox_gui.views.settings_view import SettingsView
from paradox_gui.views.timeline_view import TimelineView


class ClickableLabel(QLabel):
    from PySide6.QtCore import Signal
    clicked = Signal()
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


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
        mb = self._topmenu
        mb.setNativeMenuBar(False)  # единый вид, а не нативный macOS-стиль

        # На панели — только «Файл» и «Помощь». Пункты
        # Прогон / Вид / Настройки живут хоткеями (F5, F11, Ctrl+,),
        # но не занимают место — их содержимое и так доступно
        # вкладками и стандартными сочетаниями.
        self._menu_file(mb)
        self._menu_tools(mb)
        self._menu_help(mb)
        # Только регистрация QAction'ов, без addMenu().
        self._menu_run(mb)
        self._menu_view(mb)
        self._menu_settings(mb)

    def _apply_dark_titlebar(self) -> None:
        """Тёмный заголовок окна на Windows 10 1809+ / 11.

        Системный заголовок и menuBar Qt не читают QSS темы —
        DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE)
        единственный способ их покрасить. На прочих платформах
        no-op, поведение не меняется.
        """
        import sys as _sys
        if _sys.platform != "win32":
            return
        try:
            import ctypes
            hwnd = int(self.winId())
            # 20 — Win10 1909+ и Win11; 19 — Win10 1809/1903.
            # Пробуем 20, если dwmapi вернёт ошибку — 19.
            for attr in (20, 19):
                value = ctypes.c_int(1)
                ret = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    ctypes.c_void_p(hwnd),
                    ctypes.c_uint(attr),
                    ctypes.byref(value),
                    ctypes.sizeof(value),
                )
                if ret == 0:
                    return
        except Exception:
            # На старых сборках dwmapi может отсутствовать —
            # молча оставляем системный цвет заголовка.
            return

    def _menu_settings(self, mb) -> None:
        # Меню «Настройки» убрано с панели. Ctrl+, — хоткей окна.
        self._act_open_settings = self._act(
            tr("menu.settings"), "Ctrl+,", self._on_open_settings,
            enabled=True,
        )
        self.addAction(self._act_open_settings)

    def _menu_file(self, mb) -> None:
        m = mb.addMenu(tr("menu.file"))
        m.addAction(self._act(
            tr("menu.file.open_pcap"), "Ctrl+O", self._on_open_pcap,
        ))
        m.addAction(self._act(
            tr("menu.file.open_report"), "Ctrl+Shift+O", self._on_open_report,
        ))

        m.addSeparator()
        export = m.addMenu(tr("menu.file.export"))
        self._act_export_json = self._act(
            tr("menu.file.export.json"), slot=self._on_export_json, enabled=False,
        )
        self._act_export_md = self._act(
            tr("menu.file.export.markdown"), slot=self._on_export_md, enabled=False,
        )
        self._act_export_conn = self._act(
            tr("menu.file.export.conn_log"), slot=self._on_export_conn, enabled=False,
        )
        export.addAction(self._act_export_json)
        export.addAction(self._act_export_md)
        export.addSeparator()
        export.addAction(self._act_export_conn)

        m.addSeparator()
        m.addAction(self._act(tr("menu.file.quit"), "Ctrl+Q", self.close))

    def _menu_run(self, mb) -> None:
        self._act_analyze = self._act(
            tr("menu.run.analyze"), "F5", self._on_analyze, enabled=True,
        )
        self._act_analyze_cfg = self._act(
            tr("menu.run.analyze_with_config"), "Ctrl+F5",
            self._on_analyze_with_config, enabled=False,
        )
        self._act_stop = self._act(
            tr("menu.run.stop"), "Esc", self._on_stop, enabled=False,
        )
        for a in (self._act_analyze, self._act_analyze_cfg, self._act_stop):
            self.addAction(a)

    def _menu_view(self, mb) -> None:
        self._act_fullscreen = self._act(
            tr("menu.view.fullscreen"), "F11", self._toggle_fullscreen,
        )
        self.addAction(self._act_fullscreen)

    def _menu_tools(self, mb) -> None:
        m = mb.addMenu(tr("menu.tools"))
        m.addAction(self._act(
            tr("menu.tools.quick_check"), "Ctrl+Shift+I",
            self._on_quick_check,
        ))

    def _on_quick_check(self) -> None:
        """Открыть/показать окно быстрой проверки.

        Окно создаётся лениво и живёт как дочерний top-level виджет.
        Config собирается из текущих overrides (актуальные настройки
        пользователя), report — из последнего прогона.
        """
        try:
            from paradox_gui.config_builder import (
                build_config_with_overrides,
            )
            from paradox_gui.views.quick_check_window import (
                QuickCheckWindow,
            )
        except ImportError as e:
            QMessageBox.critical(
                self, "Ошибка", f"Не удалось загрузить окно: {e}",
            )
            return

        if getattr(self, "_quick_check", None) is None:
            overrides = {}
            if getattr(self, "_settings_store", None) is not None:
                try:
                    overrides = (
                        self._settings_store.load().get("overrides", {}) or {}
                    )
                except Exception:
                    overrides = {}
            try:
                config = build_config_with_overrides(overrides)
            except (ValueError, OSError) as e:
                QMessageBox.critical(
                    self, "Некорректные настройки", str(e),
                )
                return
            self._quick_check = QuickCheckWindow(config=config, parent=self)

        # Прокинуть актуальный report — комбо IOC обновится.
        if hasattr(self, "run_view"):
            try:
                self._quick_check.set_report(self.run_view.last_report())
            except Exception:
                pass

        self._quick_check.show()
        self._quick_check.raise_()
        self._quick_check.activateWindow()

    def _menu_help(self, mb) -> None:
        m = mb.addMenu(tr("menu.help"))
        self._act_help_reference = self._act(
            tr("menu.help.reference"), slot=self._on_help_reference,
        )
        self._act_help_about = self._act(
            tr("menu.help.about"), slot=self._on_about,
        )
        self._act_help_hotkeys = self._act(
            tr("menu.help.hotkeys"), slot=self._on_hotkeys,
        )
        m.addAction(self._act_help_reference)
        m.addSeparator()
        m.addAction(self._act_help_about)
        m.addAction(self._act_help_hotkeys)

        self._act_f1_help = self._act(
            f"{tr('menu.help.reference')} (F1)", "F1", self._on_help_reference,
        )
        self.addAction(self._act_f1_help)

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.run_view = RunView(store=self._settings_store)
        self.settings_view = SettingsView(store=self._settings_store)
        self.enrich_view = EnrichView()
        self.history_view = HistoryView()
        self.ipv6_view = IPv6View()
        self.timeline_view = TimelineView()
        self.export_view = ExportView()

        self.run_view.analysis_started.connect(self._on_analysis_started)
        self.run_view.analysis_finished.connect(self._on_analysis_finished)
        self.run_view.analysis_failed.connect(self._on_analysis_failed)
        self.run_view.analysis_cancelled.connect(self._on_analysis_cancelled)

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

        self._status_text = QLabel(tr("status.ready"))
        self._status_file = QLabel("—")
        self._status_file.setObjectName("muted")
        sb.addWidget(self._status_text)
        sb.addWidget(QLabel(tr("status.file")))
        sb.addWidget(self._status_file)

        self._version_lbl = ClickableLabel(f"v{APP_VERSION} · © v314xm")
        self._version_lbl.setStyleSheet("color: #a0a0b0; padding: 0 8px;")
        self._version_lbl.setCursor(Qt.CursorShape.PointingHandCursor)
        self._version_lbl.setToolTip(tr("dialog.about.title"))
        self._version_lbl.clicked.connect(self._on_about)
        sb.addPermanentWidget(self._version_lbl)

    def _on_open_pcap(self) -> None:
        try:
            self.tabs.setCurrentIndex(0)
            self.run_view.open_file_dialog()
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Ошибка", f"{type(e).__name__}: {e}")

    def _on_open_report(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("dialog.file.open_report.title"),
            "",
            tr("dialog.file.open_report.filter"),
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(
                self,
                tr("error.read.title"),
                tr("error.read.body", type=type(e).__name__, message=str(e)),
            )
            return
        if not isinstance(data, dict) or "findings" not in data:
            QMessageBox.critical(
                self,
                tr("error.wrong_file.title"),
                tr("error.wrong_file.body"),
            )
            return
        self.tabs.setCurrentIndex(0)
        self.run_view.load_report(data)
        self._on_analysis_finished(data)
        self.statusBar().showMessage(
            tr("status.report_loaded", path=path), 5000,
        )

    def _on_analyze(self) -> None:
        self.run_view.reanalyze()

    def _on_analyze_with_config(self) -> None:
        self.statusBar().showMessage("Анализ с настройками — после шага 12", 3000)

    def _on_stop(self) -> None:
        # >>> ОСТАНОВКА <<<
        self.run_view.stop_analysis()
        # >>> /ОСТАНОВКА <<<

    def _on_open_settings(self) -> None:
        # «Настройки» — четвёртый таб (индекс 3) после перестановки.
        self.tabs.setCurrentIndex(3)

    def _on_help_reference(self) -> None:
        QMessageBox.information(
            self,
            tr("dialog.help.title"),
            tr("dialog.help.body_html"),
        )

    def _on_about(self) -> None:
        """About-диалог с логотипом."""
        try:
            from PySide6.QtWidgets import (
                QDialog,
                QDialogButtonBox,
                QLabel,
                QVBoxLayout,
            )

            from paradox_gui.logo import render_logo

            dlg = QDialog(self)
            dlg.setWindowTitle(tr("dialog.about.title"))
            dlg.setMinimumWidth(420)
            v = QVBoxLayout(dlg)
            v.setContentsMargins(24, 24, 24, 16)
            v.setSpacing(10)

            logo_lbl = QLabel()
            logo_lbl.setPixmap(render_logo(96))
            logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.addWidget(logo_lbl)

            title = QLabel(tr("dialog.about.app_title", version=APP_VERSION))
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title.setStyleSheet(
                "font-size: 20px; font-weight: 700; color: #5b8cff;"
            )
            v.addWidget(title)

            subtitle = QLabel(tr("dialog.about.subtitle"))
            subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            subtitle.setObjectName("muted")
            v.addWidget(subtitle)

            modules = QLabel(tr("dialog.about.modules_html"))
            modules.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v.addWidget(modules)

            sep = QLabel("─" * 30)
            sep.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sep.setStyleSheet("color: #3a3d4d;")
            v.addWidget(sep)

            copyright_lbl = QLabel(tr("dialog.about.copyright"))
            copyright_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            copyright_lbl.setObjectName("muted")
            v.addWidget(copyright_lbl)

            btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            btn.rejected.connect(dlg.reject)
            btn.button(QDialogButtonBox.StandardButton.Close).setText(
                tr("btn.close")
            )
            v.addWidget(btn)

            dlg.exec()
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(
                self,
                tr("error.title"),
                f"{type(e).__name__}: {e}",
            )

    def _on_hotkeys(self) -> None:
        QMessageBox.information(
            self,
            tr("dialog.hotkeys.title"),
            tr("dialog.hotkeys.body"),
        )

    def _on_analysis_started(self, path: str) -> None:
        self._status_text.setText(tr("status.analyzing"))
        self._status_file.setText(path)
        # >>> ОСТАНОВКА <<<
        self._act_stop.setEnabled(True)
        self._act_analyze.setEnabled(False)
        # >>> /ОСТАНОВКА <<<

    def _on_analysis_finished(self, report: object) -> None:
        s = report.get("summary", {}) if isinstance(report, dict) else {}
        self._status_text.setText(tr(
            "status.done",
            findings=s.get("findings", 0),
            contradictions=s.get("contradictions", 0),
        ))
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

        # >>> IPv6 <<<
        if isinstance(report, dict) and hasattr(self, "ipv6_view"):
            self.ipv6_view.update_data(report)

        if isinstance(report, dict) and hasattr(self, "timeline_view"):
            self.timeline_view.update_data(report)

        if isinstance(report, dict) and hasattr(self, "export_view"):
            self.export_view.update_data(report)

        # >>> ОСТАНОВКА <<<
        self._act_stop.setEnabled(False)
        self._act_analyze.setEnabled(True)
        # >>> /ОСТАНОВКА <<<
        # >>> /ИСТОРИЯ <<<
    # >>> /СИГНАЛЫ ОТ RunView <<<
    # >>> ОСТАНОВКА <<<
    def _on_analysis_cancelled(self) -> None:
        self._status_text.setText(tr("status.cancelled"))
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

    def _on_compare_history(self, old_report: dict) -> None:
        """Слот на сигнал compare_requested из HistoryView.

        Пользователь выбрал в истории старый прогон и хочет сравнить
        его с тем, что сейчас открыт в RunView.
        """
        current_report = self.run_view.last_report()
        if not current_report:
            QMessageBox.information(
                self, "Нет текущего прогона",
                "Сначала выполните анализ pcap во вкладке «Прогон», чтобы "
                "было с чем сравнивать.",
            )
            return

        # Настраиваем DiffView и переключаемся на него
        self.diff_view.set_reports(old_report, current_report)

        # Ищем индекс вкладки DiffView
        idx = self.tabs.indexOf(self.diff_view)
        if idx >= 0:
            self.tabs.setCurrentIndex(idx)

    def _on_compare_history(self, old_report: dict) -> None:
        """Слот на сигнал compare_requested из HistoryView.

        Пользователь выбрал в истории старый прогон и хочет сравнить
        его с тем, что сейчас открыт в RunView.
        """
        current_report = self.run_view.last_report()
        if not current_report:
            QMessageBox.information(
                self, "Нет текущего прогона",
                "Сначала выполните анализ pcap во вкладке «Прогон», чтобы "
                "было с чем сравнивать.",
            )
            return

        # Настраиваем DiffView и переключаемся на него
        self.diff_view.set_reports(old_report, current_report)

        # Ищем индекс вкладки DiffView
        idx = self.tabs.indexOf(self.diff_view)
        if idx >= 0:
            self.tabs.setCurrentIndex(idx)

    def _on_export_json(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("dialog.file.save_json.title"),
            self._default_export_name("json"),
            tr("dialog.file.save_json.filter"),
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True),
                encoding="utf-8",
            )
            self._status_text.setText(tr("status.saved", path=path))
        except Exception as e:
            QMessageBox.critical(self, tr("error.save.title"), str(e))

    def _on_export_md(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("dialog.file.save_md.title"),
            self._default_export_name("md"),
            tr("dialog.file.save_md.filter"),
        )
        if not path:
            return
        try:
            from paradox.reporters.markdown_reporter import render_markdown
            Path(path).write_text(render_markdown(report), encoding="utf-8")
            self._status_text.setText(tr("status.saved", path=path))
        except Exception as e:
            QMessageBox.critical(self, tr("error.save.title"), str(e))

    def _on_export_conn(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("dialog.file.save_conn.title"),
            self._default_export_name("log"),
            tr("dialog.file.save_conn.filter"),
        )
        if not path:
            return
        try:
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
            self._status_text.setText(tr("status.saved", path=path))
        except Exception as e:
            QMessageBox.critical(self, tr("error.save.title"), str(e))

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
