#!/usr/bin/env python3
"""Миграционный скрипт: применяет i18n-патч к Paradox GUI.

Что делает (идемпотентно):
  1. Создаёт пакет paradox_gui/i18n/ с _ru.py и _en.py
     (удаляет старый paradox_gui/i18n.py, если он есть).
  2. Патчит paradox_gui/main_window.py — заменяет литералы
     на tr("...") во всех меню, вкладках, статус-баре и диалогах.
  3. Патчит paradox_gui/views/settings_view.py — combo языков
     и сообщение «перезапустите программу».
  4. Опционально создаёт tests/test_i18n.py — страж целостности
     словарей.

Повторный запуск — no-op (находит уже применённые маркеры).
Каждый пропатченный файл сохраняется с суффиксом .bak (дата-время
в имени), и перед записью проверяется через ast.parse.

Использование:
    python tools/apply_i18n_patch.py --dry-run
    python tools/apply_i18n_patch.py --yes
    python tools/apply_i18n_patch.py --force --yes       # перезаписать
    python tools/apply_i18n_patch.py --no-test --yes     # без test_i18n.py
"""
from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG_GUI = ROOT / "paradox_gui"
I18N_DIR = PKG_GUI / "i18n"
I18N_FILE = PKG_GUI / "i18n.py"
MAIN_WINDOW = PKG_GUI / "main_window.py"
SETTINGS_VIEW = PKG_GUI / "views" / "settings_view.py"
TEST_FILE = ROOT / "tests" / "test_i18n.py"


# =============================================================================
# Содержимое пакета paradox_gui/i18n/
# =============================================================================

I18N_INIT = r'''"""Локализация интерфейса Paradox.

Структура:
    paradox_gui/i18n/
        __init__.py   — публичный API (tr, set_language, get_language)
        _ru.py        — русские строки (дефолт)
        _en.py        — английские строки

Ключи плоские, с точками: "menu.file.open", "tab.run", "btn.cancel".
Подстановки — через str.format(): tr("app.title", version="1.2").

Поиск: текущий язык → "en" → "ru" → вернуть сам ключ.
Если ключа нет нигде — возвращается ключ (видно, что не переведено).

Добавление языка:
    1. Скопировать _ru.py → _xx.py, перевести значения.
    2. В _TRANSLATIONS ниже добавить "xx": _xx.STRINGS.
    3. В SUPPORTED_LANGUAGES добавить "xx".
    4. В _LANG_DISPLAY добавить отображаемое имя.
"""
from __future__ import annotations

import warnings

from paradox_gui.i18n import _en, _ru


#: Подключённые словари. Ключ — ISO-код языка.
_TRANSLATIONS: dict[str, dict[str, str]] = {
    "ru": _ru.STRINGS,
    "en": _en.STRINGS,
}

#: Порядок языков в выпадающем списке настроек.
SUPPORTED_LANGUAGES: tuple[str, ...] = ("ru", "en")

#: Дефолт при первом запуске / при отсутствии настройки.
DEFAULT_LANGUAGE: str = "ru"

#: Отображаемые имена языков (всегда на самом языке).
_LANG_DISPLAY: dict[str, str] = {
    "ru": "Русский",
    "en": "English",
}

#: Fallback-порядок, если ключа нет в текущем языке.
_FALLBACK_ORDER: tuple[str, ...] = ("en", "ru")

_current_lang: str = DEFAULT_LANGUAGE


def set_language(lang: str) -> None:
    """Установить текущий язык.

    Неизвестный код — предупреждение и no-op, чтобы опечатка
    в settings.json не валила GUI.
    """
    global _current_lang
    if lang in _TRANSLATIONS:
        _current_lang = lang
    else:
        warnings.warn(
            f"i18n: unsupported language {lang!r}, "
            f"expected one of {SUPPORTED_LANGUAGES}",
            stacklevel=2,
        )


def get_language() -> str:
    return _current_lang


def language_display_name(lang: str) -> str:
    """Имя языка для combo. Всегда на самом языке."""
    return _LANG_DISPLAY.get(lang, lang)


def tr(key: str, **kwargs: object) -> str:
    """Перевод по ключу с подстановкой kwargs.

    Если ключа нет ни в одном языке — возвращается сам ключ.
    Подстановка падает тихо: если в словаре {version}, а kwargs
    пустой — вернём строку как есть (лучше текст с {version},
    чем исключение в UI).
    """
    text = _lookup(key)
    if text is None:
        return key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text
    return text


def _lookup(key: str) -> str | None:
    cur = _TRANSLATIONS.get(_current_lang)
    if cur and key in cur:
        return cur[key]
    for lang in _FALLBACK_ORDER:
        d = _TRANSLATIONS.get(lang)
        if d and key in d:
            return d[key]
    return None


def validate_translations() -> dict[str, set[str]]:
    """Проверить, что словари языков покрывают одинаковые ключи.

    Возвращает {lang: set(missing_keys)}. Используется в тестах,
    не запускается автоматически.
    """
    all_keys = set()
    for d in _TRANSLATIONS.values():
        all_keys |= set(d.keys())

    out: dict[str, set[str]] = {}
    for lang, d in _TRANSLATIONS.items():
        missing = all_keys - set(d.keys())
        if missing:
            out[lang] = missing
    return out
'''


I18N_RU = r'''"""Русские строки интерфейса (дефолтный язык)."""
from __future__ import annotations

STRINGS: dict[str, str] = {
    # --- приложение / окно ---
    "app.title": "Paradox v{version}",

    # --- вкладки ---
    "tab.run": "Прогон",
    "tab.history": "История",
    "tab.enrich": "Обогащение",
    "tab.settings": "Настройки",
    "tab.ipv6": "IPv6",
    "tab.timeline": "Таймлайн",
    "tab.export": "Экспорт",
    "tab.diff": "Сравнение",

    # --- меню ---
    "menu.file": "Файл",
    "menu.file.open_pcap": "Открыть pcap…",
    "menu.file.open_report": "Открыть отчёт…",
    "menu.file.export": "Экспорт",
    "menu.file.export.json": "JSON-отчёт…",
    "menu.file.export.markdown": "Markdown-отчёт…",
    "menu.file.export.conn_log": "Flow report (conn.log)…",
    "menu.file.quit": "Выход",
    "menu.tools": "Инструменты",
    "menu.tools.quick_check": "Быстрая проверка IOC…",
    "menu.help": "Помощь",
    "menu.help.reference": "Справка",
    "menu.help.about": "О программе",
    "menu.help.hotkeys": "Горячие клавиши",
    "menu.settings": "Открыть настройки…",
    "menu.run.analyze": "Анализировать",
    "menu.run.analyze_with_config": "Анализировать с настройками…",
    "menu.run.stop": "Остановить",
    "menu.view.fullscreen": "Полноэкранный режим",

    # --- статус-бар ---
    "status.ready": "Готов",
    "status.file": "Файл:",
    "status.analyzing": "Анализ…",
    "status.done": "Готово · {findings} findings · {contradictions} противоречий",
    "status.cancelled": "Остановлено пользователем",
    "status.saved": "Сохранено: {path}",
    "status.report_loaded": "Загружен отчёт: {path}",

    # --- общие кнопки ---
    "btn.close": "Закрыть",

    # --- диалоги файлов ---
    "dialog.file.open_pcap.title": "Открыть pcap",
    "dialog.file.open_pcap.filter": "Packet captures (*.pcap *.pcapng *.cap);;Все файлы (*)",
    "dialog.file.open_report.title": "Открыть отчёт",
    "dialog.file.open_report.filter": "JSON (*.json);;Все файлы (*)",
    "dialog.file.save_json.title": "Сохранить JSON-отчёт",
    "dialog.file.save_json.filter": "JSON (*.json);;Все файлы (*)",
    "dialog.file.save_md.title": "Сохранить Markdown-отчёт",
    "dialog.file.save_md.filter": "Markdown (*.md);;Все файлы (*)",
    "dialog.file.save_conn.title": "Сохранить flow report",
    "dialog.file.save_conn.filter": "Log (*.log);;Все файлы (*)",

    # --- ошибки ---
    "error.title": "Ошибка",
    "error.read.title": "Ошибка чтения",
    "error.read.body": "{type}: {message}",
    "error.wrong_file.title": "Не тот файл",
    "error.wrong_file.body": "Это не JSON-отчёт Paradox: нет ключа 'findings'.",
    "error.save.title": "Ошибка сохранения",
    "error.config.title": "Некорректные настройки",
    "error.import.body": "Не удалось загрузить: {message}",

    # --- About ---
    "dialog.about.title": "О программе",
    "dialog.about.app_title": "Paradox v{version}",
    "dialog.about.subtitle": "Оффлайн-триаж pcap",
    "dialog.about.modules_html": (
        "<div style='text-align:center; line-height:1.6;'>"
        "<span style='color:#e0e0e0;'>"
        "20 детекторов · 12 правил<br>"
        "4 экстрактора · 4 анализатора<br>"
        "</span>"
        "<span style='color:#a0a0b0; font-size:11px;'>"
        "Attack Graph · Multi-pcap · Threat Intel<br>"
        "Shodan · AbuseIPDB · VirusTotal · OTX · URLScan"
        "</span></div>"
    ),
    "dialog.about.copyright": "© 2026 Andrey Grigoryev (v314xm)",

    # --- Help ---
    "dialog.help.title": "Справка по инструменту",
    "dialog.help.body_html": (
        "<b>Что делает Paradox</b><br>"
        "Извлекает факты о сети из pcap и ищет противоречия "
        "между слоями данных: DNS vs SNI, JA3 vs UA, MAC vs IP, "
        "роли vs поведение.<br><br>"
        "<b>Экстракторы (9):</b><br>"
        "flow, dns, host_identity, arp_history, nbns, "
        "kerberos, tls, http, <b>ndp (IPv6)</b>.<br><br>"
        "<b>Детекторы (18):</b><br>"
        "dga, cloud_tunnel, ip_check_service, typosquatting, "
        "sni_mismatch, suspicious_port, port_scan, web_scanner, "
        "brute_force, ftp_brute_force, beaconing, dns_tunneling, "
        "lateral_movement, large_transfer, vulnerable_path, "
        "command_injection, ja3_malware, nxdomain_burst, <b>yara</b>.<br><br>"
        "<b>Анализаторы:</b><br>"
        "Confidence Explainer, What-If (Counterfactual), "
        "Absence (Оборванные сессии), Host Story.<br><br>"
        "<b>Правила противоречий (12):</b><br>"
        "victim_makes_attack, mac_ip_conflict, "
        "sni_host_mismatch, ja3_ua_mismatch, reverse_asymmetry, "
        "port_service_mismatch, direct_ip_no_dns, "
        "sni_without_dns, dns_answer_mismatch, "
        "sni_cert_mismatch, self_signed_cert, "
        "expired_cert.<br><br>"
        "<i>Подробное описание каждого модуля — в отдельном "
        "релизе.</i>"
    ),

    # --- Hotkeys ---
    "dialog.hotkeys.title": "Горячие клавиши",
    "dialog.hotkeys.body": (
        "Ctrl+O — открыть pcap\n"
        "F5 — анализ\n"
        "F11 — полноэкранный режим"
    ),

    # --- язык ---
    "dialog.lang_changed.title": "Язык",
    "dialog.lang_changed.body": (
        "Язык изменён. Для полного применения перезапустите программу."
    ),
}
'''


I18N_EN = r'''"""English UI strings."""
from __future__ import annotations

STRINGS: dict[str, str] = {
    # --- app ---
    "app.title": "Paradox v{version}",

    # --- tabs ---
    "tab.run": "Run",
    "tab.history": "History",
    "tab.enrich": "Enrichment",
    "tab.settings": "Settings",
    "tab.ipv6": "IPv6",
    "tab.timeline": "Timeline",
    "tab.export": "Export",
    "tab.diff": "Diff",

    # --- menu ---
    "menu.file": "File",
    "menu.file.open_pcap": "Open pcap…",
    "menu.file.open_report": "Open report…",
    "menu.file.export": "Export",
    "menu.file.export.json": "JSON report…",
    "menu.file.export.markdown": "Markdown report…",
    "menu.file.export.conn_log": "Flow report (conn.log)…",
    "menu.file.quit": "Quit",
    "menu.tools": "Tools",
    "menu.tools.quick_check": "Quick IOC check…",
    "menu.help": "Help",
    "menu.help.reference": "Reference",
    "menu.help.about": "About",
    "menu.help.hotkeys": "Keyboard shortcuts",
    "menu.settings": "Open settings…",
    "menu.run.analyze": "Analyze",
    "menu.run.analyze_with_config": "Analyze with settings…",
    "menu.run.stop": "Stop",
    "menu.view.fullscreen": "Fullscreen",

    # --- status bar ---
    "status.ready": "Ready",
    "status.file": "File:",
    "status.analyzing": "Analyzing…",
    "status.done": "Done · {findings} findings · {contradictions} contradictions",
    "status.cancelled": "Cancelled by user",
    "status.saved": "Saved: {path}",
    "status.report_loaded": "Report loaded: {path}",

    # --- buttons ---
    "btn.close": "Close",

    # --- file dialogs ---
    "dialog.file.open_pcap.title": "Open pcap",
    "dialog.file.open_pcap.filter": "Packet captures (*.pcap *.pcapng *.cap);;All files (*)",
    "dialog.file.open_report.title": "Open report",
    "dialog.file.open_report.filter": "JSON (*.json);;All files (*)",
    "dialog.file.save_json.title": "Save JSON report",
    "dialog.file.save_json.filter": "JSON (*.json);;All files (*)",
    "dialog.file.save_md.title": "Save Markdown report",
    "dialog.file.save_md.filter": "Markdown (*.md);;All files (*)",
    "dialog.file.save_conn.title": "Save flow report",
    "dialog.file.save_conn.filter": "Log (*.log);;All files (*)",

    # --- errors ---
    "error.title": "Error",
    "error.read.title": "Read error",
    "error.read.body": "{type}: {message}",
    "error.wrong_file.title": "Wrong file",
    "error.wrong_file.body": "Not a Paradox JSON report: missing 'findings'.",
    "error.save.title": "Save error",
    "error.config.title": "Invalid settings",
    "error.import.body": "Failed to load: {message}",

    # --- About ---
    "dialog.about.title": "About",
    "dialog.about.app_title": "Paradox v{version}",
    "dialog.about.subtitle": "Offline pcap triage",
    "dialog.about.modules_html": (
        "<div style='text-align:center; line-height:1.6;'>"
        "<span style='color:#e0e0e0;'>"
        "20 detectors · 12 rules<br>"
        "4 extractors · 4 analyzers<br>"
        "</span>"
        "<span style='color:#a0a0b0; font-size:11px;'>"
        "Attack Graph · Multi-pcap · Threat Intel<br>"
        "Shodan · AbuseIPDB · VirusTotal · OTX · URLScan"
        "</span></div>"
    ),
    "dialog.about.copyright": "© 2026 Andrey Grigoryev (v314xm)",

    # --- Help ---
    "dialog.help.title": "Tool reference",
    "dialog.help.body_html": (
        "<b>What Paradox does</b><br>"
        "Extracts network facts from a pcap and looks for inconsistencies "
        "between data layers: DNS vs SNI, JA3 vs UA, MAC vs IP, "
        "roles vs behavior.<br><br>"
        "<b>Extractors (9):</b><br>"
        "flow, dns, host_identity, arp_history, nbns, "
        "kerberos, tls, http, <b>ndp (IPv6)</b>.<br><br>"
        "<b>Detectors (18):</b><br>"
        "dga, cloud_tunnel, ip_check_service, typosquatting, "
        "sni_mismatch, suspicious_port, port_scan, web_scanner, "
        "brute_force, ftp_brute_force, beaconing, dns_tunneling, "
        "lateral_movement, large_transfer, vulnerable_path, "
        "command_injection, ja3_malware, nxdomain_burst, <b>yara</b>.<br><br>"
        "<b>Analyzers:</b><br>"
        "Confidence Explainer, What-If (Counterfactual), "
        "Absence (broken sessions), Host Story.<br><br>"
        "<b>Contradiction rules (12):</b><br>"
        "victim_makes_attack, mac_ip_conflict, "
        "sni_host_mismatch, ja3_ua_mismatch, reverse_asymmetry, "
        "port_service_mismatch, direct_ip_no_dns, "
        "sni_without_dns, dns_answer_mismatch, "
        "sni_cert_mismatch, self_signed_cert, "
        "expired_cert.<br><br>"
        "<i>Detailed description of each module — in a separate "
        "release.</i>"
    ),

    # --- Hotkeys ---
    "dialog.hotkeys.title": "Keyboard shortcuts",
    "dialog.hotkeys.body": (
        "Ctrl+O — open pcap\n"
        "F5 — analyze\n"
        "F11 — fullscreen"
    ),

    # --- language ---
    "dialog.lang_changed.title": "Language",
    "dialog.lang_changed.body": (
        "Language changed. Restart the app to apply fully."
    ),
}
'''


# =============================================================================
# Новые методы main_window.py — целиком
# =============================================================================

# Карта «имя метода → маркер идемпотентности». Если маркер уже
# присутствует в файле — метод пропатчен, скипаем.
_MW_MARKERS = {
    "_menu_settings":      'tr("menu.settings")',
    "_menu_file":          'tr("menu.file")',
    "_menu_run":           'tr("menu.run.analyze")',
    "_menu_view":          'tr("menu.view.fullscreen")',
    "_menu_tools":         'tr("menu.tools")',
    "_menu_help":          'tr("menu.help")',
    "_build_statusbar":    'tr("status.ready")',
    "_build_tabs":         'tr("tab.run")',
    "_on_open_report":     'tr("dialog.file.open_report.title")',
    "_on_help_reference":  'tr("dialog.help.title")',
    "_on_about":           'tr("dialog.about.title")',
    "_on_hotkeys":         'tr("dialog.hotkeys.title")',
    "_on_export_json":     'tr("dialog.file.save_json.title")',
    "_on_export_md":       'tr("dialog.file.save_md.title")',
    "_on_export_conn":     'tr("dialog.file.save_conn.title")',
}

_NEW_MENU_SETTINGS = r'''    def _menu_settings(self, mb) -> None:
        # Меню «Настройки» убрано с панели. Ctrl+, — хоткей окна.
        self._act_open_settings = self._act(
            tr("menu.settings"), "Ctrl+,", self._on_open_settings,
            enabled=True,
        )
        self.addAction(self._act_open_settings)

'''

_NEW_MENU_FILE = r'''    def _menu_file(self, mb) -> None:
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

'''

_NEW_MENU_RUN = r'''    def _menu_run(self, mb) -> None:
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

'''

_NEW_MENU_VIEW = r'''    def _menu_view(self, mb) -> None:
        self._act_fullscreen = self._act(
            tr("menu.view.fullscreen"), "F11", self._toggle_fullscreen,
        )
        self.addAction(self._act_fullscreen)

'''

_NEW_MENU_TOOLS = r'''    def _menu_tools(self, mb) -> None:
        m = mb.addMenu(tr("menu.tools"))
        m.addAction(self._act(
            tr("menu.tools.quick_check"), "Ctrl+Shift+I",
            self._on_quick_check,
        ))

'''

_NEW_MENU_HELP = r'''    def _menu_help(self, mb) -> None:
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

'''

_NEW_BUILD_STATUSBAR = r'''    def _build_statusbar(self) -> None:
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

'''

_NEW_ON_OPEN_REPORT = r'''    def _on_open_report(self) -> None:
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

'''

_NEW_ON_HELP_REFERENCE = r'''    def _on_help_reference(self) -> None:
        QMessageBox.information(
            self,
            tr("dialog.help.title"),
            tr("dialog.help.body_html"),
        )

'''

_NEW_ON_ABOUT = r'''    def _on_about(self) -> None:
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

'''

_NEW_ON_HOTKEYS = r'''    def _on_hotkeys(self) -> None:
        QMessageBox.information(
            self,
            tr("dialog.hotkeys.title"),
            tr("dialog.hotkeys.body"),
        )

'''

_NEW_ON_EXPORT_JSON = r'''    def _on_export_json(self) -> None:
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

'''

_NEW_ON_EXPORT_MD = r'''    def _on_export_md(self) -> None:
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

'''

_NEW_ON_EXPORT_CONN = r'''    def _on_export_conn(self) -> None:
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

'''

_NEW_BUILD_TABS = r'''    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        from paradox_gui.settings_store import SettingsStore
        self._settings_store = SettingsStore()

        _saved_lang = self._settings_store.load().get("language", "ru")
        set_language(_saved_lang)

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

'''

_NEW_METHODS: dict[str, str] = {
    "_menu_settings":      _NEW_MENU_SETTINGS,
    "_menu_file":          _NEW_MENU_FILE,
    "_menu_run":           _NEW_MENU_RUN,
    "_menu_view":          _NEW_MENU_VIEW,
    "_menu_tools":         _NEW_MENU_TOOLS,
    "_menu_help":          _NEW_MENU_HELP,
    "_build_statusbar":    _NEW_BUILD_STATUSBAR,
    "_build_tabs":         _NEW_BUILD_TABS,
    "_on_open_report":     _NEW_ON_OPEN_REPORT,
    "_on_help_reference":  _NEW_ON_HELP_REFERENCE,
    "_on_about":           _NEW_ON_ABOUT,
    "_on_hotkeys":         _NEW_ON_HOTKEYS,
    "_on_export_json":     _NEW_ON_EXPORT_JSON,
    "_on_export_md":       _NEW_ON_EXPORT_MD,
    "_on_export_conn":     _NEW_ON_EXPORT_CONN,
}


# =============================================================================
# Helper: замена метода по имени до следующего def на том же уровне
# =============================================================================

def _replace_method(text: str, name: str, new_body: str) -> tuple[str, bool]:
    """Найти '    def <name>(self...' и заменить до следующего '    def '.

    Возвращает (new_text, found). Если метод не найден — текст не меняется.
    """
    pat = re.compile(
        rf"    def {re.escape(name)}\(self.*?(?=^    def |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pat.search(text)
    if not m:
        return text, False
    return text[:m.start()] + new_body + text[m.end():], True


def _validate_python(source: str, path: Path) -> None:
    """Проверить синтаксис через ast.parse."""
    try:
        ast.parse(source)
    except SyntaxError as e:
        raise RuntimeError(
            f"после патча {path.name} содержит синтаксическую ошибку: "
            f"строка {e.lineno}: {e.msg}"
        )


def _backup(path: Path) -> Path:
    """Сохранить копию файла с датой-временем в имени."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = path.with_name(f"{path.name}.{ts}.bak")
    shutil.copy2(path, bak)
    return bak


# =============================================================================
# Шаг 1: пакет paradox_gui/i18n/
# =============================================================================

def create_i18n_package(dry_run: bool, force: bool) -> bool:
    """Создать пакет paradox_gui/i18n/ с тремя файлами.

    Возвращает True если что-то изменилось.
    """
    changed = False

    # 1. Удалить старый модуль paradox_gui/i18n.py, если он есть.
    if I18N_FILE.exists():
        if dry_run:
            print(f"  [dry] удалить {I18N_FILE.relative_to(ROOT)}")
        else:
            bak = _backup(I18N_FILE)
            I18N_FILE.unlink()
            print(f"  удалён {I18N_FILE.relative_to(ROOT)} (бэкап: {bak.name})")
        changed = True

    # 2. Создать директорию (если нет).
    if not I18N_DIR.exists():
        if dry_run:
            print(f"  [dry] создать директорию {I18N_DIR.relative_to(ROOT)}")
        else:
            I18N_DIR.mkdir(parents=True, exist_ok=True)
            print(f"  создана директория {I18N_DIR.relative_to(ROOT)}")
        changed = True

    # 3. Записать три файла.
    files = {
        I18N_DIR / "__init__.py": I18N_INIT,
        I18N_DIR / "_ru.py": I18N_RU,
        I18N_DIR / "_en.py": I18N_EN,
    }
    for path, content in files.items():
        if path.exists() and not force:
            # Проверить: старое содержимое совпадает? (по маркеру)
            if 'SUPPORTED_LANGUAGES' in path.read_text(encoding="utf-8"):
                print(f"  {path.relative_to(ROOT)} уже пропатчен, скип")
                continue
        if dry_run:
            print(f"  [dry] записать {path.relative_to(ROOT)} ({len(content)} байт)")
        else:
            if path.exists():
                _backup(path)
            path.write_text(content, encoding="utf-8")
            print(f"  записан {path.relative_to(ROOT)} ({len(content)} байт)")
        changed = True

    return changed


# =============================================================================
# Шаг 2: main_window.py
# =============================================================================

def patch_main_window(dry_run: bool, force: bool) -> bool:
    if not MAIN_WINDOW.exists():
        print(f"  [warn] {MAIN_WINDOW.relative_to(ROOT)} не найден, пропускаем",
              file=sys.stderr)
        return False

    text = MAIN_WINDOW.read_text(encoding="utf-8")
    original = text

    # 2.1. Убрать TAB_TITLES (мёртвая константа).
    text = re.sub(
        r"^TAB_TITLES\s*=\s*\([^)]*\)\n+",
        "",
        text,
        count=1,
        flags=re.MULTILINE,
    )

    # 2.2. Заголовок окна.
    text = text.replace(
        'self.setWindowTitle(f"Paradox v{APP_VERSION}")',
        'self.setWindowTitle(tr("app.title", version=APP_VERSION))',
    )

    # 2.3. Заменить методы целиком.
    for name, body in _NEW_METHODS.items():
        marker = _MW_MARKERS.get(name)
        if not force and marker and marker in text:
            print(f"  {name}: уже пропатчен, скип")
            continue
        text, found = _replace_method(text, name, body)
        if not found:
            print(f"  [warn] метод {name!r} не найден в main_window.py",
                  file=sys.stderr)

    # 2.4. Точечные замены для _on_analysis_* (только строки статуса).
    text = text.replace(
        '        self._status_text.setText("Анализ…")',
        '        self._status_text.setText(tr("status.analyzing"))',
    )
    text = text.replace(
        '''        self._status_text.setText(
            f"Готово · {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий"
        )''',
        '''        self._status_text.setText(tr(
            "status.done",
            findings=s.get("findings", 0),
            contradictions=s.get("contradictions", 0),
        ))''',
    )
    text = text.replace(
        '        self._status_text.setText("Остановлено пользователем")',
        '        self._status_text.setText(tr("status.cancelled"))',
    )

    if text == original:
        print("  main_window.py: изменений нет")
        return False

    _validate_python(text, MAIN_WINDOW)

    if dry_run:
        print(f"  [dry] записать {MAIN_WINDOW.relative_to(ROOT)} "
              f"({len(text)} байт, было {len(original)})")
        return True

    bak = _backup(MAIN_WINDOW)
    MAIN_WINDOW.write_text(text, encoding="utf-8")
    print(f"  записан {MAIN_WINDOW.relative_to(ROOT)} "
          f"(бэкап: {bak.name})")
    return True


# =============================================================================
# Шаг 3: settings_view.py
# =============================================================================

_OLD_LANG_COMBO = r'''        self._lang_combo = QComboBox()
        self._lang_combo.addItem("Русский", "ru")
        self._lang_combo.addItem("English", "en")

        # Загружаем текущий язык
        if self._store:
            current_lang = self._store.load().get("language", "ru")
            idx = self._lang_combo.findData(current_lang)
            if idx >= 0:
                self._lang_combo.setCurrentIndex(idx)
'''

_NEW_LANG_COMBO = r'''        self._lang_combo = QComboBox()
        for _code in SUPPORTED_LANGUAGES:
            self._lang_combo.addItem(language_display_name(_code), _code)

        # Загружаем текущий язык
        if self._store:
            current_lang = self._store.load().get("language", DEFAULT_LANGUAGE)
            idx = self._lang_combo.findData(current_lang)
            if idx >= 0:
                self._lang_combo.setCurrentIndex(idx)
'''

_OLD_LANG_CHANGED = r'''    def _on_lang_changed(self, index: int) -> None:
        lang = self._lang_combo.itemData(index)
        if self._store and lang:
            self._store.save_partial(language=lang)
            QMessageBox.information(
                self, "Язык",
                "Язык изменён. Для полного применения перезапустите программу.",
            )
'''

_NEW_LANG_CHANGED = r'''    def _on_lang_changed(self, index: int) -> None:
        lang = self._lang_combo.itemData(index)
        if self._store and lang:
            self._store.save_partial(language=lang)
            QMessageBox.information(
                self,
                tr("dialog.lang_changed.title"),
                tr("dialog.lang_changed.body"),
            )
'''

_I18N_IMPORT = (
    "from paradox_gui.i18n import (\n"
    "    DEFAULT_LANGUAGE,\n"
    "    SUPPORTED_LANGUAGES,\n"
    "    language_display_name,\n"
    "    tr,\n"
    ")\n"
)


def patch_settings_view(dry_run: bool, force: bool) -> bool:
    if not SETTINGS_VIEW.exists():
        print(f"  [warn] {SETTINGS_VIEW.relative_to(ROOT)} не найден",
              file=sys.stderr)
        return False

    text = SETTINGS_VIEW.read_text(encoding="utf-8")
    original = text

    if not force and 'SUPPORTED_LANGUAGES' in text:
        print("  settings_view.py: уже пропатчен, скип")
        return False

    if _OLD_LANG_COMBO in text:
        text = text.replace(_OLD_LANG_COMBO, _NEW_LANG_COMBO)
    else:
        print("  [warn] settings_view.py: не найден блок combo языков",
              file=sys.stderr)

    if _OLD_LANG_CHANGED in text:
        text = text.replace(_OLD_LANG_CHANGED, _NEW_LANG_CHANGED)
    else:
        print("  [warn] settings_view.py: не найден _on_lang_changed",
              file=sys.stderr)

    # Добавить импорт i18n, если ещё нет.
    if "from paradox_gui.i18n import" not in text:
        # Вставить перед 'from paradox_gui.widgets.editable_list import'
        anchor = "from paradox_gui.widgets.editable_list import ("
        if anchor in text:
            text = text.replace(anchor, _I18N_IMPORT + "\n" + anchor, 1)
        else:
            print("  [warn] settings_view.py: anchor для импорта не найден",
                  file=sys.stderr)

    if text == original:
        print("  settings_view.py: изменений нет")
        return False

    _validate_python(text, SETTINGS_VIEW)

    if dry_run:
        print(f"  [dry] записать {SETTINGS_VIEW.relative_to(ROOT)} "
              f"({len(text)} байт, было {len(original)})")
        return True

    bak = _backup(SETTINGS_VIEW)
    SETTINGS_VIEW.write_text(text, encoding="utf-8")
    print(f"  записан {SETTINGS_VIEW.relative_to(ROOT)} "
          f"(бэкап: {bak.name})")
    return True


# =============================================================================
# Шаг 4: tests/test_i18n.py
# =============================================================================

_TEST_I18N = r'''"""Страж целостности словарей i18n."""
from paradox_gui.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    validate_translations,
)


def test_all_languages_cover_same_keys():
    """Никаких «забытых» ключей в одном из языков."""
    missing = validate_translations()
    assert not missing, (
        "В словарях языков разное число ключей:\n"
        + "\n".join(
            f"  {lang}: {sorted(keys)}"
            for lang, keys in missing.items()
        )
    )


def test_default_language_in_supported():
    assert DEFAULT_LANGUAGE in SUPPORTED_LANGUAGES


def test_at_least_two_languages():
    """Международность = минимум два языка."""
    assert len(SUPPORTED_LANGUAGES) >= 2


def test_tr_returns_key_for_unknown():
    """Неизвестный ключ возвращается как есть — видно, что не переведено."""
    from paradox_gui.i18n import tr
    assert tr("__definitely_not_a_real_key__") == "__definitely_not_a_real_key__"


def test_tr_substitution():
    """format-подстановка работает."""
    from paradox_gui.i18n import tr
    out = tr("app.title", version="9.9")
    assert "9.9" in out
'''


def create_test_file(dry_run: bool, force: bool) -> bool:
    if TEST_FILE.exists() and not force:
        print(f"  {TEST_FILE.relative_to(ROOT)} уже существует, скип")
        return False
    if dry_run:
        print(f"  [dry] записать {TEST_FILE.relative_to(ROOT)}")
        return True
    _validate_python(_TEST_I18N, TEST_FILE)
    TEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    if TEST_FILE.exists():
        _backup(TEST_FILE)
    TEST_FILE.write_text(_TEST_I18N, encoding="utf-8")
    print(f"  записан {TEST_FILE.relative_to(ROOT)}")
    return True


# =============================================================================
# Точка входа
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Применить i18n-патч к Paradox GUI.",
    )
    ap.add_argument("--dry-run", action="store_true",
                    help="только показать, что будет изменено")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="не спрашивать подтверждения")
    ap.add_argument("--force", action="store_true",
                    help="перезаписать даже если уже пропатчено")
    ap.add_argument("--no-test", action="store_true",
                    help="не создавать tests/test_i18n.py")
    args = ap.parse_args(argv)

    if not PKG_GUI.is_dir():
        print(f"error: {PKG_GUI} не найдена. Запускать из корня проекта?",
              file=sys.stderr)
        return 2

    print("i18n-patch для Paradox GUI")
    print(f"  ROOT: {ROOT}")
    print()

    if not args.dry_run and not args.yes:
        print("Будут изменены файлы:")
        print("  • paradox_gui/i18n.py → удалён (заменяется пакетом)")
        print("  • paradox_gui/i18n/ ← создан (3 файла)")
        print("  • paradox_gui/main_window.py ← патч меню/вкладок/диалогов")
        print("  • paradox_gui/views/settings_view.py ← combo языков")
        if not args.no_test:
            print("  • tests/test_i18n.py ← создан (если нет)")
        print()
        print("Бэкапы сохраняются как <file>.<timestamp>.bak.")
        print()
        answer = input("Продолжить? [y/N] ").strip().lower()
        if answer not in ("y", "yes", "да"):
            print("Отменено.")
            return 1

    total_changed = 0

    print("[1/4] пакет paradox_gui/i18n/")
    if create_i18n_package(args.dry_run, args.force):
        total_changed += 1
    print()

    print("[2/4] paradox_gui/main_window.py")
    if patch_main_window(args.dry_run, args.force):
        total_changed += 1
    print()

    print("[3/4] paradox_gui/views/settings_view.py")
    if patch_settings_view(args.dry_run, args.force):
        total_changed += 1
    print()

    if not args.no_test:
        print("[4/4] tests/test_i18n.py")
        if create_test_file(args.dry_run, args.force):
            total_changed += 1
        print()
    else:
        print("[4/4] tests/test_i18n.py — пропущено (--no-test)")
        print()

    if args.dry_run:
        print(f"[dry-run] изменений: {total_changed}. "
              f"Запусти без --dry-run, чтобы применить.")
        return 0

    if total_changed == 0:
        print("Нечего делать — всё уже пропатчено.")
        return 0

    print(f"Готово. Изменено файлов: {total_changed}.")
    print()
    print("Дальше:")
    print("  python -m pytest tests/test_i18n.py -v")
    print("  python -m paradox_gui          # проверить, что GUI стартует")
    print()
    print("Переключение языка: Настройки → Общие → Язык интерфейса.")
    print("После смены — перезапустить приложение.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
