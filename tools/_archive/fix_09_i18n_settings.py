# tools/fix_09_i18n_settings.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "09-i18n-settings"
TITLE = "i18n: перевод заголовков и полей в SettingsView"
REL_RU = "paradox_gui/i18n/_ru.py"
REL_EN = "paradox_gui/i18n/_en.py"
REL_SETTINGS = "paradox_gui/views/settings_view.py"

# --- 1. Добавить ключи в _ru.py ---
_RU_OLD = '''    "settings.placeholder.general": "<b>Что будет.</b> Общие настройки: <b>язык интерфейса</b> (русский / английский), путь к отчётам по умолчанию, поведение при старте (открывать последний pcap или пустую вкладку), тема оформления (сейчас тёмная — единственная).<br><br><b>Почему пусто.</b> Сейчас эти значения либо захардкожены в GUI, либо не критичны. Появятся, когда появится вторая локализация или несколько профилей работы.",
    "settings.placeholder.fallback": "Секция в разработке.",
    "settings.help.fallback": "Параметр «{field}» из Config ядра. См. paradox/config.py.",

}'''
_RU_NEW = '''    "settings.placeholder.general": "<b>Что будет.</b> Общие настройки: <b>язык интерфейса</b> (русский / английский), путь к отчётам по умолчанию, поведение при старте (открывать последний pcap или пустую вкладку), тема оформления (сейчас тёмная — единственная).<br><br><b>Почему пусто.</b> Сейчас эти значения либо захардкожены в GUI, либо не критичны. Появятся, когда появится вторая локализация или несколько профилей работы.",
    "settings.placeholder.fallback": "Секция в разработке.",
    "settings.help.fallback": "Параметр «{field}» из Config ядра. См. paradox/config.py.",

    # --- Новые ключи для UI (v1.2) ---
    "settings.yara.browse": "Обзор…",
    "settings.yara.validate": "Проверить правила",
    "settings.yara.path": "Путь к файлу правил (.yar):",
    "settings.brute.skip_tls_label": "HTTP: порты, где brute force не ищем (TLS)",
    "settings.brute.login_hints_label": "HTTP: подсказки login-endpoint",
    "settings.network.suspicious_ports": "Подозрительные порты",
    "settings.network.scan_excluded": "Исключения port scan",
    "settings.network.dc_ports": "Порты domain controller",
    "settings.network.lateral_ports": "Порты lateral movement",
    "settings.network.mail_ports": "Порты mail-polling (POP3/IMAP)",
    "settings.network.private_nets": "Префиксы приватных сетей",
    "settings.perf.reassembly": "Склеивать TCP-сегменты (TCP Reassembly)",
    "settings.perf.carve": "Извлекать метаданные файлов (File Carve)",
    "settings.perf.write_body": "Сохранять тела файлов на диск (ОПАСНО)",
    "settings.allowlist.beaconing_suffixes": "Beaconing: суффиксы SNI/Host (analytics, CDN)",
    "settings.allowlist.beaconing_ips": "Beaconing: точные IP (без SNI)",
    "settings.allowlist.dns_tunneling": "DNS tunneling: DoH-домены, не считать туннелем",
    "settings.allowlist.sni_mismatch": "SNI mismatch: известные проверочные домены",
    "settings.allowlist.large_transfer_hosts": "Large transfer: хосты, для которых это норма",
    "settings.allowlist.large_transfer_uas": "Large transfer: UA, для которых это норма",
    "settings.dga.allowlist_label": "DGA allowlist (домены)",
    "settings.threatintel.providers": "Активные провайдеры",
    "settings.threatintel.abuseipdb_key": "AbuseIPDB API key",
    "settings.threatintel.vt_key": "VirusTotal API key",
    "settings.threatintel.abusech_key": "abuse.ch Auth-Key",
    "settings.threatintel.otx_key": "AlienVault OTX API key",
    "settings.threatintel.greynoise_key": "GreyNoise API key",
    "settings.threatintel.urlscan_key": "URLScan API key",
    "settings.threatintel.show_keys": "Показать ключи",
    "settings.threatintel.cache_ttl": "Кэш: TTL (дней)",
    "settings.threatintel.cache_path": "Кэш: путь к SQLite-файлу",
    "settings.threatintel.max_iocs": "Максимум IOC за прогон",

}'''

# --- 2. Добавить ключи в _en.py ---
_EN_OLD = '''    "settings.placeholder.general": "<b>What's coming.</b> General settings: <b>UI language</b> (Russian / English), default reports path, startup behavior (open last pcap or empty tab), theme (currently dark-only).<br><br><b>Why empty.</b> Currently these values are either hardcoded in GUI or not critical. Will appear with the second locale or multiple work profiles.",
    "settings.placeholder.fallback": "Section in development.",
    "settings.help.fallback": "Config field '{field}'. See paradox/config.py.",

}'''
_EN_NEW = '''    "settings.placeholder.general": "<b>What's coming.</b> General settings: <b>UI language</b> (Russian / English), default reports path, startup behavior (open last pcap or empty tab), theme (currently dark-only).<br><br><b>Why empty.</b> Currently these values are either hardcoded in GUI or not critical. Will appear with the second locale or multiple work profiles.",
    "settings.placeholder.fallback": "Section in development.",
    "settings.help.fallback": "Config field '{field}'. See paradox/config.py.",

    # --- New keys for UI (v1.2) ---
    "settings.yara.browse": "Browse…",
    "settings.yara.validate": "Validate rules",
    "settings.yara.path": "Rules file path (.yar):",
    "settings.brute.skip_tls_label": "HTTP: ports to skip for brute force (TLS)",
    "settings.brute.login_hints_label": "HTTP: login-endpoint hints",
    "settings.network.suspicious_ports": "Suspicious ports",
    "settings.network.scan_excluded": "Port scan exclusions",
    "settings.network.dc_ports": "Domain controller ports",
    "settings.network.lateral_ports": "Lateral movement ports",
    "settings.network.mail_ports": "Mail polling ports (POP3/IMAP)",
    "settings.network.private_nets": "Private network prefixes",
    "settings.perf.reassembly": "Reassemble TCP segments (TCP Reassembly)",
    "settings.perf.carve": "Extract file metadata (File Carve)",
    "settings.perf.write_body": "Write file bodies to disk (DANGEROUS)",
    "settings.allowlist.beaconing_suffixes": "Beaconing: SNI/Host suffixes (analytics, CDN)",
    "settings.allowlist.beaconing_ips": "Beaconing: exact IPs (no SNI)",
    "settings.allowlist.dns_tunneling": "DNS tunneling: DoH domains, not a tunnel",
    "settings.allowlist.sni_mismatch": "SNI mismatch: known validation domains",
    "settings.allowlist.large_transfer_hosts": "Large transfer: hosts where this is normal",
    "settings.allowlist.large_transfer_uas": "Large transfer: UAs where this is normal",
    "settings.dga.allowlist_label": "DGA allowlist (domains)",
    "settings.threatintel.providers": "Active providers",
    "settings.threatintel.abuseipdb_key": "AbuseIPDB API key",
    "settings.threatintel.vt_key": "VirusTotal API key",
    "settings.threatintel.abusech_key": "abuse.ch Auth-Key",
    "settings.threatintel.otx_key": "AlienVault OTX API key",
    "settings.threatintel.greynoise_key": "GreyNoise API key",
    "settings.threatintel.urlscan_key": "URLScan API key",
    "settings.threatintel.show_keys": "Show keys",
    "settings.threatintel.cache_ttl": "Cache: TTL (days)",
    "settings.threatintel.cache_path": "Cache: SQLite file path",
    "settings.threatintel.max_iocs": "Max IOCs per run",

}'''

# --- 3. Обновить settings_view.py ---
_MAKE_HEADER_OLD = '''    def _make_header(self, title: str, subtitle: str) -> tuple[QLabel, QLabel]:
        t = QLabel(title)
        t.setObjectName("h1")
        s = QLabel(subtitle)
        s.setObjectName("muted")
        s.setWordWrap(True)
        section_key = SECTION_BY_TITLE.get(title)
        if section_key:
            help_text = get_section_help(section_key)
            if help_text:
                t.setToolTip(help_text)
                s.setToolTip(help_text)
        return t, s
'''
_MAKE_HEADER_NEW = '''    def _make_header(self, title: str, subtitle: str, section_key: str | None = None) -> tuple[QLabel, QLabel]:
        t = QLabel(title)
        t.setObjectName("h1")
        s = QLabel(subtitle)
        s.setObjectName("muted")
        s.setWordWrap(True)
        if section_key is None:
            section_key = SECTION_BY_TITLE.get(title)
        if section_key:
            help_text = get_section_help(section_key)
            if help_text:
                t.setToolTip(help_text)
                s.setToolTip(help_text)
        return t, s
'''

_THRESH_OLD = '''        t, s = self._make_header(
            "Пороги",
            "Пороги детекторов из Config ядра. Изменения применяются "
            "к следующему прогону. Профиль — готовый набор значений.",
        )'''
_THRESH_NEW = '''        t, s = self._make_header(
            tr("settings.thresholds.title"),
            tr("settings.thresholds.subtitle"),
            "thresholds",
        )'''

_BRUTE_OLD = '''        t, s = self._make_header(
            "Brute force",
            "Как детектор отличает подбор пароля от обычного трафика. "
            "Пороги «сколько flows» — в разделе Пороги.",
        )'''
_BRUTE_NEW = '''        t, s = self._make_header(
            tr("settings.brute.title"),
            tr("settings.brute.subtitle"),
            "brute",
        )'''

_NET_OLD = '''        t, s = self._make_header(
            "Сеть",
            "Списки портов и префиксов. Вводите через запятую или с новой строки. "
            "Невалидные значения подсвечиваются и не сохраняются.",
        )'''
_NET_NEW = '''        t, s = self._make_header(
            tr("settings.network.title"),
            tr("settings.network.subtitle"),
            "network",
        )'''

_PERF_OLD = '''        t, s = self._make_header(
            "Производительность",
            "Компромисс между глубиной анализа и скоростью. "
            "Технические лимиты (память, размеры) скрыты и работают "
            "по умолчанию.",
        )'''
_PERF_NEW = '''        t, s = self._make_header(
            tr("settings.perf.title"),
            tr("settings.perf.subtitle"),
            "perf",
        )'''

_ALLOW_OLD = '''        t, s = self._make_header(
            "Allowlist",
            "Белые списки. Совпадение с элементом убирает кандидата из "
            "findings. Один элемент на строку, # — комментарий.",
        )'''
_ALLOW_NEW = '''        t, s = self._make_header(
            tr("settings.allowlist.title"),
            tr("settings.allowlist.subtitle"),
            "allowlist",
        )'''

_DGA_OLD = '''        t, s = self._make_header(
            "DGA",
            "Итоговый allowlist детектора DGA. Сюда сливаются домены "
            "cloud tunnel и IP-check сервисов из Config. Удаление "
            "элемента означает, что DGA начнёт ругаться на него.",
        )'''
_DGA_NEW = '''        t, s = self._make_header(
            tr("settings.dga.title"),
            tr("settings.dga.subtitle"),
            "dga",
        )'''

_YARA_OLD = '''        t, s = self._make_header(
            "YARA",
            "Пользовательские YARA-правила для поиска сигнатур в payload. "
            "Если файл не выбран, используются стандартные правила из ядра.",
        )'''
_YARA_NEW = '''        t, s = self._make_header(
            tr("settings.yara.title"),
            tr("settings.yara.subtitle"),
            "yara",
        )'''

_REPORTS_OLD = '''        t, s = self._make_header(
            "Отчёты",
            "Куда ядро складывает артефакты (кэш обогащения, carved files "
            "при включённой записи). Путь создаётся при применении.",
        )'''
_REPORTS_NEW = '''        t, s = self._make_header(
            tr("settings.reports.title"),
            tr("settings.reports.subtitle"),
            "reports",
        )'''

_TI_OLD = '''        t, s = self._make_header(
            "Threat Intel",
            "Обогащение IOC из findings. Запускается отдельно (флаг "
            "--enrich). API-ключи живут до перезапуска GUI — ядро читает "
            "их из переменных окружения в момент запроса.",
        )'''
_TI_NEW = '''        t, s = self._make_header(
            tr("settings.threatintel.title"),
            tr("settings.threatintel.subtitle"),
            "threatintel",
        )'''

_DET_OLD = '''        t, s = self._make_header(
            "Детекторы",
            "Снятая галочка отключает детектор в следующем прогоне. "
            "Порядок совпадает с ядром.",
        )'''
_DET_NEW = '''        t, s = self._make_header(
            tr("settings.detectors.title"),
            tr("settings.detectors.subtitle"),
            "detectors",
        )'''

_CONTRA_OLD = '''        t, s = self._make_header(
            "ContradictionDetector",
            "Правила проверяют согласованность между слоями данных. "
            "Отключение правила убирает его из следующего прогона.",
        )'''
_CONTRA_NEW = '''        t, s = self._make_header(
            tr("settings.contradictions.title"),
            tr("settings.contradictions.subtitle"),
            "contradictions",
        )'''

# Поля и кнопки
_BRUTE_FIELDS_OLD = '''        self._bf_skip_tls = EditableListWidget(port_mode=True)
        form.addRow("HTTP: порты, где brute force не ищем (TLS)", self._bf_skip_tls)
        self._brute_inputs["brute_force_skip_tls_ports"] = self._bf_skip_tls

        self._bf_login_hints = EditableListWidget(port_mode=False)
        form.addRow("HTTP: подсказки login-endpoint", self._bf_login_hints)
        self._brute_inputs["login_endpoint_hints"] = self._bf_login_hints
'''
_BRUTE_FIELDS_NEW = '''        self._bf_skip_tls = EditableListWidget(port_mode=True)
        form.addRow(tr("settings.brute.skip_tls_label"), self._bf_skip_tls)
        self._brute_inputs["brute_force_skip_tls_ports"] = self._bf_skip_tls

        self._bf_login_hints = EditableListWidget(port_mode=False)
        form.addRow(tr("settings.brute.login_hints_label"), self._bf_login_hints)
        self._brute_inputs["login_endpoint_hints"] = self._bf_login_hints
'''

_NET_FIELDS_OLD = '''        self._add_smart_net_row(form, "suspicious_ports", "Подозрительные порты", is_net=False)
        self._add_smart_net_row(form, "port_scan_excluded_ports", "Исключения port scan", is_net=False)
        self._add_smart_net_row(form, "dc_service_ports", "Порты domain controller", is_net=False)
        self._add_smart_net_row(form, "lateral_movement_ports", "Порты lateral movement", is_net=False)
        self._add_smart_net_row(form, "beaconing_mail_polling_ports", "Порты mail-polling (POP3/IMAP)", is_net=False)
        self._add_smart_net_row(form, "private_networks", "Префиксы приватных сетей", is_net=True)
'''
_NET_FIELDS_NEW = '''        self._add_smart_net_row(form, "suspicious_ports", tr("settings.network.suspicious_ports"), is_net=False)
        self._add_smart_net_row(form, "port_scan_excluded_ports", tr("settings.network.scan_excluded"), is_net=False)
        self._add_smart_net_row(form, "dc_service_ports", tr("settings.network.dc_ports"), is_net=False)
        self._add_smart_net_row(form, "lateral_movement_ports", tr("settings.network.lateral_ports"), is_net=False)
        self._add_smart_net_row(form, "beaconing_mail_polling_ports", tr("settings.network.mail_ports"), is_net=False)
        self._add_smart_net_row(form, "private_networks", tr("settings.network.private_nets"), is_net=True)
'''

_PERF_FIELDS_OLD = '''        cb_reassembly = QCheckBox("Склеивать TCP-сегменты (TCP Reassembly)")'''
_PERF_FIELDS_NEW = '''        cb_reassembly = QCheckBox(tr("settings.perf.reassembly"))'''

_PERF_FIELDS_OLD_2 = '''        cb_carve = QCheckBox("Извлекать метаданные файлов (File Carve)")'''
_PERF_FIELDS_NEW_2 = '''        cb_carve = QCheckBox(tr("settings.perf.carve"))'''

_PERF_FIELDS_OLD_3 = '''        cb_write = QCheckBox("Сохранять тела файлов на диск (ОПАСНО)")'''
_PERF_FIELDS_NEW_3 = '''        cb_write = QCheckBox(tr("settings.perf.write_body"))'''

_ALLOW_FIELDS_OLD = '''        self._add_list_row_al(form, "beaconing_allowlist_suffixes",
                              "Beaconing: суффиксы SNI/Host (analytics, CDN)",
                              height=200)
        self._add_list_row_al(form, "beaconing_allowlist_ips",
                              "Beaconing: точные IP (без SNI)",
                              height=80)
        self._add_list_row_al(form, "dns_tunneling_allowlist",
                              "DNS tunneling: DoH-домены, не считать туннелем",
                              height=80)
        self._add_list_row_al(form, "sni_mismatch_allowlist",
                              "SNI mismatch: известные проверочные домены",
                              height=140)
        self._add_list_row_al(form, "large_transfer_excluded_hosts",
                              "Large transfer: хосты, для которых это норма",
                              height=120)
        self._add_list_row_al(form, "large_transfer_excluded_user_agents",
                              "Large transfer: UA, для которых это норма",
                              height=80)
'''
_ALLOW_FIELDS_NEW = '''        self._add_list_row_al(form, "beaconing_allowlist_suffixes",
                              tr("settings.allowlist.beaconing_suffixes"),
                              height=200)
        self._add_list_row_al(form, "beaconing_allowlist_ips",
                              tr("settings.allowlist.beaconing_ips"),
                              height=80)
        self._add_list_row_al(form, "dns_tunneling_allowlist",
                              tr("settings.allowlist.dns_tunneling"),
                              height=80)
        self._add_list_row_al(form, "sni_mismatch_allowlist",
                              tr("settings.allowlist.sni_mismatch"),
                              height=140)
        self._add_list_row_al(form, "large_transfer_excluded_hosts",
                              tr("settings.allowlist.large_transfer_hosts"),
                              height=120)
        self._add_list_row_al(form, "large_transfer_excluded_user_agents",
                              tr("settings.allowlist.large_transfer_uas"),
                              height=80)
'''

_DGA_FIELD_OLD = '''        form.addRow("DGA allowlist (домены)", self._dga_allowlist)'''
_DGA_FIELD_NEW = '''        form.addRow(tr("settings.dga.allowlist_label"), self._dga_allowlist)'''

_YARA_FIELDS_OLD = '''        btn_browse = QPushButton("Обзор…")'''
_YARA_FIELDS_NEW = '''        btn_browse = QPushButton(tr("settings.yara.browse"))'''

_YARA_FIELDS_OLD_2 = '''        btn_validate = QPushButton("Проверить правила")'''
_YARA_FIELDS_NEW_2 = '''        btn_validate = QPushButton(tr("settings.yara.validate"))'''

_YARA_FIELDS_OLD_3 = '''        form.addRow("Путь к файлу правил (.yar):", row)'''
_YARA_FIELDS_NEW_3 = '''        form.addRow(tr("settings.yara.path"), row)'''

_TI_FIELDS_OLD_1 = '''        form.addRow("Активные провайдеры", te_prov)'''
_TI_FIELDS_NEW_1 = '''        form.addRow(tr("settings.threatintel.providers"), te_prov)'''

_TI_FIELDS_OLD_2 = '''        form.addRow("AbuseIPDB API key", self._ti_abuse_key)'''
_TI_FIELDS_NEW_2 = '''        form.addRow(tr("settings.threatintel.abuseipdb_key"), self._ti_abuse_key)'''

_TI_FIELDS_OLD_3 = '''        form.addRow("VirusTotal API key", self._ti_vt_key)'''
_TI_FIELDS_NEW_3 = '''        form.addRow(tr("settings.threatintel.vt_key"), self._ti_vt_key)'''

_TI_FIELDS_OLD_4 = '''        form.addRow("abuse.ch Auth-Key", self._ti_abusech_key)'''
_TI_FIELDS_NEW_4 = '''        form.addRow(tr("settings.threatintel.abusech_key"), self._ti_abusech_key)'''

_TI_FIELDS_OLD_5 = '''        form.addRow("AlienVault OTX API key", self._ti_otx_key)'''
_TI_FIELDS_NEW_5 = '''        form.addRow(tr("settings.threatintel.otx_key"), self._ti_otx_key)'''

_TI_FIELDS_OLD_6 = '''        form.addRow("GreyNoise API key", self._ti_greynoise_key)'''
_TI_FIELDS_NEW_6 = '''        form.addRow(tr("settings.threatintel.greynoise_key"), self._ti_greynoise_key)'''

_TI_FIELDS_OLD_7 = '''        form.addRow("URLScan API key", self._ti_urlscan_key)'''
_TI_FIELDS_NEW_7 = '''        form.addRow(tr("settings.threatintel.urlscan_key"), self._ti_urlscan_key)'''

_TI_FIELDS_OLD_8 = '''        show_cb = QCheckBox("Показать ключи")'''
_TI_FIELDS_NEW_8 = '''        show_cb = QCheckBox(tr("settings.threatintel.show_keys"))'''

_TI_FIELDS_OLD_9 = '''        form.addRow("Кэш: TTL (дней)", sp_ttl)'''
_TI_FIELDS_NEW_9 = '''        form.addRow(tr("settings.threatintel.cache_ttl"), sp_ttl)'''

_TI_FIELDS_OLD_10 = '''        form.addRow("Кэш: путь к SQLite-файлу", le_cache)'''
_TI_FIELDS_NEW_10 = '''        form.addRow(tr("settings.threatintel.cache_path"), le_cache)'''

_TI_FIELDS_OLD_11 = '''        form.addRow("Максимум IOC за прогон", sp_max)'''
_TI_FIELDS_NEW_11 = '''        form.addRow(tr("settings.threatintel.max_iocs"), sp_max)'''

_CONTRA_BTN_OLD = '''        all_btn = QPushButton("Включить все")
        all_btn.clicked.connect(lambda: self._set_all_contradictions(True))
        none_btn = QPushButton("Отключить все")
        none_btn.clicked.connect(lambda: self._set_all_contradictions(False))
        buttons.addWidget(all_btn)
        buttons.addWidget(none_btn)
        buttons.addStretch(1)
        apply_btn = QPushButton("Применить")
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_contradictions)
        buttons.addWidget(apply_btn)'''
_CONTRA_BTN_NEW = '''        all_btn = QPushButton(tr("settings.btn.enable_all"))
        all_btn.clicked.connect(lambda: self._set_all_contradictions(True))
        none_btn = QPushButton(tr("settings.btn.disable_all"))
        none_btn.clicked.connect(lambda: self._set_all_contradictions(False))
        buttons.addWidget(all_btn)
        buttons.addWidget(none_btn)
        buttons.addStretch(1)
        apply_btn = QPushButton(tr("settings.btn.apply"))
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_contradictions)
        buttons.addWidget(apply_btn)'''

_DET_BTN_OLD_2 = '''        apply_btn = QPushButton("Применить")
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_detectors)'''
_DET_BTN_NEW_2 = '''        apply_btn = QPushButton(tr("settings.btn.apply"))
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_detectors)'''


def apply(root: Path) -> bool:
    changed = False

    # RU & EN strings
    if patch(root, REL_RU, _RU_OLD, _RU_NEW, required=False): changed = True
    if patch(root, REL_EN, _EN_OLD, _EN_NEW, required=False): changed = True

    # make_header
    if patch(root, REL_SETTINGS, _MAKE_HEADER_OLD, _MAKE_HEADER_NEW, required=False): changed = True

    # pages
    for old, new in [
        (_THRESH_OLD, _THRESH_NEW),
        (_BRUTE_OLD, _BRUTE_NEW),
        (_NET_OLD, _NET_NEW),
        (_PERF_OLD, _PERF_NEW),
        (_ALLOW_OLD, _ALLOW_NEW),
        (_DGA_OLD, _DGA_NEW),
        (_YARA_OLD, _YARA_NEW),
        (_REPORTS_OLD, _REPORTS_NEW),
        (_TI_OLD, _TI_NEW),
        (_DET_OLD, _DET_NEW),
        (_CONTRA_OLD, _CONTRA_NEW),
    ]:
        if patch(root, REL_SETTINGS, old, new, required=False): changed = True

    # fields and buttons
    for old, new in [
        (_BRUTE_FIELDS_OLD, _BRUTE_FIELDS_NEW),
        (_NET_FIELDS_OLD, _NET_FIELDS_NEW),
        (_PERF_FIELDS_OLD, _PERF_FIELDS_NEW),
        (_PERF_FIELDS_OLD_2, _PERF_FIELDS_NEW_2),
        (_PERF_FIELDS_OLD_3, _PERF_FIELDS_NEW_3),
        (_ALLOW_FIELDS_OLD, _ALLOW_FIELDS_NEW),
        (_DGA_FIELD_OLD, _DGA_FIELD_NEW),
        (_YARA_FIELDS_OLD, _YARA_FIELDS_NEW),
        (_YARA_FIELDS_OLD_2, _YARA_FIELDS_NEW_2),
        (_YARA_FIELDS_OLD_3, _YARA_FIELDS_NEW_3),
        (_TI_FIELDS_OLD_1, _TI_FIELDS_NEW_1),
        (_TI_FIELDS_OLD_2, _TI_FIELDS_NEW_2),
        (_TI_FIELDS_OLD_3, _TI_FIELDS_NEW_3),
        (_TI_FIELDS_OLD_4, _TI_FIELDS_NEW_4),
        (_TI_FIELDS_OLD_5, _TI_FIELDS_NEW_5),
        (_TI_FIELDS_OLD_6, _TI_FIELDS_NEW_6),
        (_TI_FIELDS_OLD_7, _TI_FIELDS_NEW_7),
        (_TI_FIELDS_OLD_8, _TI_FIELDS_NEW_8),
        (_TI_FIELDS_OLD_9, _TI_FIELDS_NEW_9),
        (_TI_FIELDS_OLD_10, _TI_FIELDS_NEW_10),
        (_TI_FIELDS_OLD_11, _TI_FIELDS_NEW_11),
        (_CONTRA_BTN_OLD, _CONTRA_BTN_NEW),
        (_DET_BTN_OLD_2, _DET_BTN_NEW_2),
    ]:
        if patch(root, REL_SETTINGS, old, new, required=False): changed = True

    if not fix_utils.DRY_RUN:
        for rel in (REL_RU, REL_EN, REL_SETTINGS):
            text = (root / rel).read_text(encoding="utf-8")
            if "settings.yara.browse" not in text and rel in (REL_RU, REL_EN):
                raise FixError(f"{rel}: не удалось применить")
            if "tr(\"settings.brute.skip_tls_label\")" not in text and rel == REL_SETTINGS:
                raise FixError(f"{rel}: не удалось применить")
    return changed
