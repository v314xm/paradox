"""Часть главного окна: menus."""
from __future__ import annotations

from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QMessageBox,
)

from paradox_gui.i18n import tr
from paradox_gui.views.payload_window import PayloadWindow
from paradox_gui.window.shortcuts import _cyr_variant


class MenusMixin:
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
        self._act_payload = self._act(
            tr("menu.tools.payload"), "Ctrl+Shift+P",
            self._on_payload_window,
        )
        m.addAction(self._act_payload)


    def _on_payload_window(self) -> None:
        """Открыть/показать окно «Код инжекта» с текущим отчётом.

        Окно живёт отдельно от вкладок: его можно держать рядом с
        основным и не терять при переключении отчёта. При новом
        прогоне MainWindow сам обновит его, если окно создано.
        """
        if getattr(self, "_payload_window", None) is None:
            # Без parent: окно должно жить самостоятельной жизнью и не
            # прятаться вместе с главным при сворачивании.
            self._payload_window = PayloadWindow()

        report = self.run_view.last_report() if hasattr(
            self, "run_view",
        ) else None
        self._payload_window.set_report(report)
        self._payload_window.show()
        self._payload_window.raise_()
        self._payload_window.activateWindow()


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
                self,
                tr("error.title"),
                tr("error.load_window.body", message=e),
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
                    self, tr("error.config.title"), str(e),
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
