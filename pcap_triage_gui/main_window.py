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
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QStackedWidget,
    QTabBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# >>> ИМПОРТЫ VIEWS <<<
from pcap_triage_gui.views.run_view import RunView
from pcap_triage_gui.views.settings_view import SettingsView
from pcap_triage_gui.views.enrich_view import EnrichView
from pcap_triage_gui.views.history_view import HistoryView
from pcap_triage_gui.views.ipv6_view import IPv6View
# >>> /ИМПОРТЫ VIEWS <<<


TAB_TITLES = ("Прогон", "История", "Обогащение", "Настройки", "IPv6")
APP_VERSION = "0.9.1"


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
            "Открыть настройки…", "Ctrl+,", self._on_open_settings,
            enabled=True,
        )
        self.addAction(self._act_open_settings)
    def _menu_file(self, mb) -> None:
        m = mb.addMenu("Файл")
        m.addAction(self._act("Открыть pcap…", "Ctrl+O", self._on_open_pcap))
        m.addAction(self._act(
            "Открыть отчёт…", "Ctrl+Shift+O", self._on_open_report,
        ))

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
        # Меню «Прогон» убрано с панели. F5 / Ctrl+F5 / Esc
        # остаются хоткеями окна. QAction'ы нужны
        # MainWindow._on_analysis_* для enable/disable.
        self._act_analyze = self._act(
            "Анализировать", "F5", self._on_analyze, enabled=True,
        )
        self._act_analyze_cfg = self._act(
            "Анализировать с настройками…", "Ctrl+F5",
            self._on_analyze_with_config, enabled=False,
        )
        self._act_stop = self._act(
            "Остановить", "Esc", self._on_stop, enabled=False,
        )
        for a in (self._act_analyze, self._act_analyze_cfg,
                  self._act_stop):
            self.addAction(a)

    def _menu_view(self, mb) -> None:
        # Меню «Вид» убрано с панели. F11 остаётся хоткеем окна.
        self._act_fullscreen = self._act(
            "Полноэкранный режим", "F11", self._toggle_fullscreen,
        )
        self.addAction(self._act_fullscreen)

    def _menu_tools(self, mb) -> None:
        m = mb.addMenu("Инструменты")
        m.addAction(self._act(
            "Быстрая проверка IOC…", "Ctrl+Shift+I",
            self._on_quick_check,
        ))

    def _on_quick_check(self) -> None:
        """Открыть/показать окно быстрой проверки.

        Окно создаётся лениво и живёт как дочерний top-level виджет.
        Config собирается из текущих overrides (актуальные настройки
        пользователя), report — из последнего прогона.
        """
        try:
            from pcap_triage_gui.config_builder import (
                build_config_with_overrides,
            )
            from pcap_triage_gui.views.quick_check_window import (
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
        m = mb.addMenu("Помощь")
        m.addAction(self._act(
            "Справка", slot=self._on_help_reference,
        ))
        m.addSeparator()
        m.addAction(self._act("О программе", slot=self._on_about))
        m.addAction(self._act("Горячие клавиши", slot=self._on_hotkeys))

    # =========================================================================
    # TABS
    # =========================================================================

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Создаём все view'шки сразу. Порядок создания не связан с
        # порядком вкладок: settings_view нужен раньше, чем мы будем
        # подключать его сигналы к enrich_view, а вкладку при этом
        # показываем после Обогащения.
        # Единый SettingsStore: один и тот же settings.json читают и
        # пишут оба view. Два разных экземпляра = расходящееся состояние.
        from pcap_triage_gui.settings_store import SettingsStore
        self._settings_store = SettingsStore()

        self.run_view = RunView(store=self._settings_store)
        self.settings_view = SettingsView(store=self._settings_store)
        self.enrich_view = EnrichView()
        self.history_view = HistoryView()
        self.ipv6_view = IPv6View()

        # --- Прогон → главное окно ---
        self.run_view.analysis_started.connect(self._on_analysis_started)
        self.run_view.analysis_finished.connect(self._on_analysis_finished)
        self.run_view.analysis_failed.connect(self._on_analysis_failed)
        self.run_view.analysis_cancelled.connect(self._on_analysis_cancelled)

        # --- Настройки → Прогон и Обогащение ---
        # thresholds_applied — отдельный сигнал для Порогов, шлёт плоский dict.
        # config_applied — общий сигнал остальных секций (Brute force, Сеть,
        # Производительность, Allowlist, DGA, Threat Intel, Отчёты).
        # Оба идут в run_view через dict.update (мердж), чтобы применения
        # разных секций не затирали друг друга.
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
        # Config (Threat Intel: провайдеры, кэш, лимит IOC) → Обогащение.
        self.settings_view.config_applied.connect(
            self.enrich_view.set_config_overrides
        )

        # --- Обогащение → История ---
        # После обогащения report мутирован in-place; История должна
        # перерисовать текущую запись, иначе секция «Обогащение» не
        # появится до повторного клика.
        self.enrich_view.enrichment_finished.connect(
            self._on_enrichment_finished
        )

        # --- Вкладки: Прогон · История · Обогащение · Настройки · Развитие ---
        # addTab последовательно = порядок кода = порядок вкладок.
        # История сразу после Прогона: смотреть прошлые результаты
        # приходится чаще, чем менять настройки или обогащать.
        self.tabs.addTab(self.run_view, TAB_TITLES[0])
        self.tabs.addTab(self.history_view, TAB_TITLES[1])
        self.tabs.addTab(self.enrich_view, TAB_TITLES[2])
        self.tabs.addTab(self.settings_view, TAB_TITLES[3])
        self.tabs.addTab(self.ipv6_view, TAB_TITLES[4])

        # Меню — отдельный QMenuBar НАД табами. QMainWindow с одним
        # setCentralWidget не покажет self._topmenu, если он не внутри
        # центрального виджета. Оборачиваем всё в контейнер с QVBox:
        # меню сверху, табы растягиваются ниже.
        container = QWidget()
        vbox = QVBoxLayout(container)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(self._topmenu)
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

    def _on_open_report(self) -> None:
        """Загрузить JSON-отчёт, сохранённый через «Экспорт → JSON».

        Прогон не запускается: JSON подаётся туда же, где оказался бы
        результат run_pipeline — в _on_analysis_finished. Значит,
        summary / contradictions / findings / история / обогащение
        заполняются так же, как после обычного прогона.
        """
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть отчёт", "",
            "JSON (*.json);;Все файлы (*)",
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(
                self, "Ошибка чтения", f"{type(e).__name__}: {e}",
            )
            return
        if not isinstance(data, dict) or "findings" not in data:
            QMessageBox.critical(
                self, "Не тот файл",
                "Это не JSON-отчёт pcap-triage: нет ключа 'findings'.",
            )
            return
        self.tabs.setCurrentIndex(0)
        # Сначала заполняем RunView, потом рассылаем в
        # историю / обогащение / статус-бар. Порядок важен:
        # load_report не эмитит analysis_finished, поэтому
        # дубликата записи в Истории не будет.
        self.run_view.load_report(data)
        self._on_analysis_finished(data)
        self.statusBar().showMessage(f"Загружен отчёт: {path}", 5000)

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
        """Заглушка справки: экстракторы, детекторы, правила.

        Полноценное содержимое будет отдельно — с описанием
        каждого модуля, что он ищет и на что обращать внимание.
        Сейчас — компактный список, чтобы пользователь видел
        состав инструмента, а не пустое окно.
        """
        QMessageBox.information(
            self,
            "Справка по инструменту",
            "<b>Что делает pcap-triage</b><br>"
            "Извлекает факты о сети из pcap и ищет противоречия "
            "между слоями данных: DNS vs SNI, JA3 vs UA, MAC vs IP, "
            "роли vs поведение.<br><br>"
            "<b>Экстракторы (8):</b><br>"
            "flow, dns, host_identity, arp_history, nbns, "
            "kerberos, tls, http.<br><br>"
            "<b>Детекторы (17):</b><br>"
            "dga, cloud_tunnel, ip_check_service, typosquatting, "
            "sni_mismatch, suspicious_port, port_scan, web_scanner, "
            "brute_force, ftp_brute_force, beaconing, dns_tunneling, "
            "lateral_movement, large_transfer, vulnerable_path, "
            "command_injection, ja3_malware, nxdomain_burst.<br><br>"
            "<b>Правила противоречий (12):</b><br>"
            "victim_makes_attack, mac_ip_conflict, "
            "sni_host_mismatch, ja3_ua_mismatch, reverse_asymmetry, "
            "port_service_mismatch, direct_ip_no_dns, "
            "sni_without_dns, dns_answer_mismatch, "
            "sni_cert_mismatch, self_signed_cert, "
            "expired_cert.<br><br>"
            "<i>Подробное описание каждого модуля — в отдельном "
            "релизе.</i>",
        )

    def _on_about(self) -> None:
        QMessageBox.about(
            self,
            "О программе",
            f"<b>pcap-triage v{APP_VERSION}</b><br><br>"
            "Оффлайн-триаж pcap.<br>"
            "17 детекторов · 8 экстракторов · 12 правил ContradictionDetector.",
            f"<br><br>© 2026 Andrey Grigoryev (v314xm)",
            f"<br><br>© 2026 Andrey Grigoryev (v314xm)",
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

        # >>> IPv6 <<<
        if isinstance(report, dict) and hasattr(self, "ipv6_view"):
            self.ipv6_view.update_data(report)

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