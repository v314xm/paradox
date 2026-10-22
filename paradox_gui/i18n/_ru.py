"""Русские строки интерфейса (дефолтный язык)."""
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
    # --- SettingsView (этап 1) ---
    "settings.section.general": "Общие",
    "settings.section.thresholds": "Пороги",
    "settings.section.detectors": "Детекторы",
    "settings.section.contradictions": "Противоречия",
    "settings.section.allowlist": "Allowlist",
    "settings.section.dga": "DGA",
    "settings.section.brute": "Brute force",
    "settings.section.network": "Сеть",
    "settings.section.reports": "Отчёты",
    "settings.section.yara": "YARA",
    "settings.section.threatintel": "Threat Intel",
    "settings.section.perf": "Производительность",
    "settings.general.title": "Общие настройки",
    "settings.general.subtitle": "Базовые параметры интерфейса.",
    "settings.thresholds.title": "Пороги",
    "settings.thresholds.subtitle": "Пороги детекторов из Config ядра. Изменения применяются к следующему прогону. Профиль — готовый набор значений.",
    "settings.detectors.title": "Детекторы",
    "settings.detectors.subtitle": "Снятая галочка отключает детектор в следующем прогоне. Порядок совпадает с ядром.",
    "settings.contradictions.title": "ContradictionDetector",
    "settings.contradictions.subtitle": "Правила проверяют согласованность между слоями данных. Отключение правила убирает его из следующего прогона.",
    "settings.allowlist.title": "Allowlist",
    "settings.allowlist.subtitle": "Белые списки. Совпадение с элементом убирает кандидата из findings. Один элемент на строку, # — комментарий.",
    "settings.dga.title": "DGA",
    "settings.dga.subtitle": "Итоговый allowlist детектора DGA. Сюда сливаются домены cloud tunnel и IP-check сервисов из Config. Удаление элемента означает, что DGA начнёт ругаться на него.",
    "settings.brute.title": "Brute force",
    "settings.brute.subtitle": "Как детектор отличает подбор пароля от обычного трафика. Пороги «сколько flows» — в разделе Пороги.",
    "settings.network.title": "Сеть",
    "settings.network.subtitle": "Списки портов и префиксов. Вводите через запятую или с новой строки. Невалидные значения подсвечиваются и не сохраняются.",
    "settings.reports.title": "Отчёты",
    "settings.reports.subtitle": "Куда ядро складывает артефакты (кэш обогащения, carved files при включённой записи). Путь создаётся при применении.",
    "settings.yara.title": "YARA",
    "settings.yara.subtitle": "Пользовательские YARA-правила для поиска сигнатур в payload. Если файл не выбран, используются стандартные правила из ядра.",
    "settings.threatintel.title": "Threat Intel",
    "settings.threatintel.subtitle": "Обогащение IOC из findings. Запускается отдельно (флаг --enrich). API-ключи живут до перезапуска GUI — ядро читает их из переменных окружения в момент запроса.",
    "settings.perf.title": "Производительность",
    "settings.perf.subtitle": "Компромисс между глубиной анализа и скоростью. Технические лимиты (память, размеры) скрыты и работают по умолчанию.",
    "settings.search.placeholder": "Поиск по настройкам (Ctrl+F)…",
    "settings.btn.reset": "Сбросить к default",
    "settings.btn.apply": "Применить",
    "settings.btn.enable_all": "Включить все",
    "settings.btn.disable_all": "Отключить все",
    "settings.profile.label": "Профиль:",
    "settings.profile.apply": "Применить профиль",
    "settings.general.language": "Язык интерфейса:",

    # --- SettingsView fields (этап 2) ---
    "settings.field.dga_min_label_length": "DGA: минимальная длина label",
    "settings.field.dga_entropy_threshold": "DGA: порог энтропии",
    "settings.field.nxdomain_burst_threshold": "NXDOMAIN burst: порог",
    "settings.field.nxdomain_burst_window_sec": "NXDOMAIN burst: окно (сек)",
    "settings.field.nxdomain_burst_min_ratio": "NXDOMAIN burst: мин. доля NXDOMAIN",
    "settings.field.dns_tunneling_min_qname_length": "DNS tunneling: мин. длина qname",
    "settings.field.dns_tunneling_min_queries": "DNS tunneling: мин. запросов",
    "settings.field.brute_force_min_flows": "Brute force: мин. flows",
    "settings.field.brute_force_max_avg_packets": "Brute force: макс. avg packets",
    "settings.field.ftp_brute_force_min_flows": "FTP brute force: мин. flows",
    "settings.field.beaconing_min_connections": "Beaconing: мин. соединений",
    "settings.field.beaconing_min_duration_sec": "Beaconing: мин. длительность (сек)",
    "settings.field.beaconing_max_jitter_ratio": "Beaconing: макс. jitter",
    "settings.field.large_transfer_min_bytes": "Large transfer: мин. байт",
    "settings.field.port_scan_min_distinct_dsts": "Port scan: мин. dsts",
    "settings.field.port_scan_max_flows_per_dst": "Port scan: макс. flows/dst",
    "settings.field.reverse_asymmetry_min_ratio": "Reverse asymmetry: мин. ratio",
    "settings.field.reverse_asymmetry_min_total_bytes": "Reverse asymmetry: мин. байт",
    "settings.field.brute_force_min_unique_src_ports": "HTTP: мин. уникальных src-портов",
    "settings.field.brute_force_uri_ratio_threshold": "HTTP: доля запросов к login-endpoint",
    "settings.field.brute_force_min_rate_flows_per_sec": "HTTP: мин. скорость (flows/сек)",
    "settings.field.ftp_brute_force_min_unique_src_ports": "FTP: мин. уникальных src-портов",
    "settings.help.dga_min_label_length": "Минимальная длина label (часть домена до первой точки). Короче — DGA не считаем, слишком много легитимных доменов.",
    "settings.help.dga_entropy_threshold": "Порог энтропии Шеннона для label. Выше — похоже на случайный набор символов (xg7f2k9vbn).",
    "settings.help.nxdomain_burst_threshold": "Сколько NXDOMAIN-ответов в окне считать burst'ом.",
    "settings.help.nxdomain_burst_window_sec": "Размер окна в секундах. Проверяется максимум во всех окнах длиной W от одного src.",
    "settings.help.nxdomain_burst_min_ratio": "Минимальная доля NXDOMAIN среди всех DNS-запросов от src. Ниже — шум (браузер с редкими опечатками).",
    "settings.help.dns_tunneling_min_qname_length": "Минимальная длина qname для DNS-туннеля. Короче — это DGA-зона, не туннель.",
    "settings.help.dns_tunneling_min_queries": "Минимум DNS-запросов к одному базовому домену, чтобы считать это туннелем.",
    "settings.help.brute_force_min_flows": "Минимум flows для HTTP brute force.",
    "settings.help.brute_force_max_avg_packets": "Максимум среднего числа пакетов на flow. Больше — уже не брутфорс (браузер грузит сайт).",
    "settings.help.ftp_brute_force_min_flows": "Минимум flows для FTP brute force. FTP-сессия длиннее, поэтому порог выше.",
    "settings.help.beaconing_min_connections": "Минимум соединений к одной паре (src, dst, port) для beaconing.",
    "settings.help.beaconing_min_duration_sec": "Минимальная длительность наблюдения. Короткий всплеск — не C2-heartbeat.",
    "settings.help.beaconing_max_jitter_ratio": "Максимальный jitter = stddev / mean интервалов. Меньше — ровнее тайминг, сильнее сигнал C2.",
    "settings.help.large_transfer_min_bytes": "Порог «большой трансфер» в байтах.",
    "settings.help.port_scan_min_distinct_dsts": "Минимум уникальных dst-адресов от одного src для port scan.",
    "settings.help.port_scan_max_flows_per_dst": "Максимум flows на один dst. Больше — это уже работа с сервисом, не скан.",
    "settings.help.reverse_asymmetry_min_ratio": "Во сколько раз большая сторона сессии должна превышать меньшую. 10:1 — аномалия, 25:1 — почти односторонний канал.",
    "settings.help.reverse_asymmetry_min_total_bytes": "Минимальный суммарный объём сессии. Ниже — не смотрим.",
    "settings.help.brute_force_min_unique_src_ports": "Минимум уникальных src-портов. Сильный сигнал подбора пароля.",
    "settings.help.brute_force_uri_ratio_threshold": "Доля запросов к login-endpoint от всех. Ниже — не брутфорс.",
    "settings.help.brute_force_min_rate_flows_per_sec": "Минимальная скорость flows/сек. Отсекает медленные легитимные повторы.",
    "settings.help.ftp_brute_force_min_unique_src_ports": "Минимум уникальных src-портов для FTP brute force.",
    "settings.help.brute_force_skip_tls_ports": "Порты с TLS, где brute force не ищем: там User-Agent не читается, признак не работает.",
    "settings.help.login_endpoint_hints": "Подстроки URI, по которым определяем login-endpoint: /login, /admin, /wp-login, …",
    "settings.help.suspicious_ports": "Порты, которые считаются подозрительными: 4444, 31337, 1337…",
    "settings.help.port_scan_excluded_ports": "Порты, которые исключаем из port scan — типичный web-трафик.",
    "settings.help.dc_service_ports": "Порты domain controller: Kerberos, LDAP, SMB. Их наличие + много flows отличает DC от обычного сервера.",
    "settings.help.lateral_movement_ports": "Порты lateral movement: SMB, RDP, WinRM, MSRPC.",
    "settings.help.beaconing_mail_polling_ports": "POP3/IMAP-порты. Почтовый клиент дёргает ящик по таймеру — это не C2-beaconing.",
    "settings.help.private_networks": "Префиксы приватных сетей. Используется для классификации dst как «внутренний» или «внешний».",
    "settings.help.tcp_reassembly_enabled": "Склеивать TCP-сегменты в потоки. Даёт полные ClientHello и HTTP body, но расходует память.",
    "settings.help.tcp_reassembly_max_bytes_per_flow": "Лимит памяти на один flow при reassembly.",
    "settings.help.tcp_reassembly_max_total_bytes": "Общий лимит памяти на reassembly. Защита от гигабайтных pcap.",
    "settings.help.file_carve_enabled": "Извлекать метаданные payload'ов (sha256, тип, размер). Без записи содержимого на диск.",
    "settings.help.file_carve_write_body": "Писать тела файлов на диск как <sha256>.bin. Осторожно: много места.",
    "settings.help.file_carve_min_size": "Минимальный размер payload для file carve.",
    "settings.help.file_carve_max_size": "Максимальный размер payload для file carve.",
    "settings.help.entities_top_n": "Сколько top-сущностей (по активности) показывать в отчёте.",
    "settings.help.flow_report_top_n": "Сколько top-flow'ов по байтам включать в flow report.",
    "settings.help.beaconing_allowlist_suffixes": "Суффиксы SNI/Host, для которых beaconing не считаем: analytics, CDN, cloud.",
    "settings.help.beaconing_allowlist_ips": "Точные IP без SNI, для которых beaconing не считаем.",
    "settings.help.dns_tunneling_allowlist": "DoH-домены: dns.google, cloudflare-dns.com. Не считать туннелем.",
    "settings.help.sni_mismatch_allowlist": "Известные проверочные домены (OCSP, CRL, DoH), у которых SNI ≠ Host штатно.",
    "settings.help.large_transfer_excluded_hosts": "Хосты, для которых большие трансферы норма: обновления Windows, Apple.",
    "settings.help.large_transfer_excluded_user_agents": "User-Agent'ы, для которых большие трансферы норма: BITS, CryptoAPI, Delivery Optimization.",
    "settings.help.dga_allowlist": "Итоговый allowlist DGA = extra + cloud tunnel + ip-check сервисы. Удаление элемента означает, что DGA начнёт ругаться на этот домен.",
    "settings.help.output_dir": "Каталог для отчётов и артефактов. Создаётся при применении.",
    "settings.help.enrichment_enabled_providers": "Какие провайдеры использовать. Без ключа: shodan_internetdb, greynoise, alienvault_otx, urlscan. С ключом: abuseipdb, virustotal. С ABUSECH_AUTH_KEY: urlhaus, malwarebazaar, threatfox.",
    "settings.help.enrichment_cache_ttl_days": "TTL кэша обогащения в днях.",
    "settings.help.enrichment_cache_path": "Путь к SQLite-файлу кэша обогащения.",
    "settings.help.enrichment_max_iocs": "Сколько IOC обогащать за один прогон.",
    "settings.placeholder.general": "<b>Что будет.</b> Общие настройки: <b>язык интерфейса</b> (русский / английский), путь к отчётам по умолчанию, поведение при старте (открывать последний pcap или пустую вкладку), тема оформления (сейчас тёмная — единственная).<br><br><b>Почему пусто.</b> Сейчас эти значения либо захардкожены в GUI, либо не критичны. Появятся, когда появится вторая локализация или несколько профилей работы.",
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

    # --- Timeline ---
    "timeline.title": "Хронология инцидента по фазам Kill-Chain",
    "timeline.no_events": "Хронология инцидента (событий не найдено)",
    "timeline.events_count": "Хронология инцидента (Событий: {count})",
    "timeline.search_placeholder": "Поиск по IP, типу или MITRE...",
    "timeline.expand_all": "Развернуть все",
    "timeline.collapse_all": "Свернуть все",
    "timeline.no_selection": "Кликните на событие, чтобы увидеть детали.",
    "timeline.phase_selected": "Выбрана фаза. Кликните на конкретное событие.",
    "timeline.phase_label": "Фаза:",
    "timeline.confidence_label": "Confidence:",
    "timeline.reasons_label": "Почему детектор так решил:",
    "timeline.evidence_label": "Дополнительные данные (Evidence):",
    "timeline.description_label": "Полное описание:",

    # --- History ---
    "history.title": "История",
    "history.subtitle": "Прогоны текущей сессии. Клик по записи — детали справа. История не сохраняется между запусками.",
    "history.empty": "Прогонов пока нет. Откройте pcap во вкладке «Прогон».",
    "history.cleared": "История очищена.",
    "history.clear_button": "Очистить историю",
    "history.ctx_compare": "Сравнить с текущим прогоном…",

    # --- QuickCheck ---
    "quick_check.title": "Проверить IOC",
    "quick_check.subtitle": "Введите IP, домен, URL или SHA256. Тип определится автоматически. Опрошены будут все включённые провайдеры.",
    "quick_check.input_placeholder": "8.8.8.8 · evil.com · https://evil.com/x · <sha256>",
    "quick_check.check_button": "Проверить",
    "quick_check.from_last_run": "Из последнего прогона:",
    "quick_check.no_data": "— нет данных —",
    "quick_check.no_run": "— нет данных (запустите прогон) —",
    "quick_check.no_iocs": "— в прогоне нет IOC —",
    "quick_check.select_ioc": "— выберите IOC —",
    "quick_check.type_detected": "Определён тип: {type}",
    "quick_check.type_unknown": "Тип не определён — выберите вручную",
    "quick_check.warning_type": "Тип не определён",
    "quick_check.warning_type_body": "Не удалось автоматически определить тип IOC. Выберите тип в выпадающем списке.",
    "quick_check.no_providers": "Нет провайдеров",
    "quick_check.no_providers_body": "Ни один провайдер не поддерживает тип «{type}». Проверьте Настройки → Threat Intel.",
    "quick_check.querying": "Опрос {count} провайдеров для {ioc} ({type})…",
    "quick_check.done": "Готово: {count} провайдеров ответили для {ioc}.",
    "quick_check.no_results": "Ни один провайдер не ответил.",
    "quick_check.error": "Ошибка: {msg}",
    "quick_check.auto": "Авто",

    # --- Export ---
    "export.title": "Экспорт данных (SIEM / Threat Intelligence)",
    "export.subtitle": "Вы можете выгрузить Findings и IOC в формате CSV (для Excel) или STIX 2.1 (для SIEM/EDR).",
    "export.fmt_csv": "CSV (Findings)",
    "export.fmt_stix": "STIX 2.1 (IOC Bundle)",
    "export.copy": "Копировать в буфер",
    "export.save": "Сохранить в файл...",
    "export.empty": "Нет данных. Сначала выполните анализ pcap.",
    "export.copied": "Полные данные скопированы в буфер обмена.\nМожно вставлять в SIEM или текстовый редактор.",
    "export.csv_saved": "CSV успешно сохранен.",
    "export.stix_saved": "STIX Bundle успешно сохранен.",
    "export.err_save": "Ошибка сохранения",

    # --- Diff ---
    "diff.title": "Сравнение прогонов",
    "diff.subtitle": "Загрузите два JSON-отчёта (старый и новый) — увидите, что добавилось, что исчезло, что изменилось. Удобно при повторном триаже одного и того же pcap через день/неделю.",
    "diff.load_old": "Загрузить старый…",
    "diff.load_new": "Загрузить новый…",
    "diff.placeholder": "Загрузите оба отчёта, чтобы увидеть сравнение.",
    "diff.export_md": "Экспорт в Markdown…",
    "diff.err_file": "Ошибка чтения",
    "diff.wrong_file": "Не тот файл",
    "diff.wrong_file_body": "Не JSON-отчёт Paradox: нет ключа 'findings'.",
    "diff.expected_json": "Ожидается JSON-отчёт.",
    "diff.not_paradox": "Это не JSON-отчёт Paradox.",
    "diff.no_changes": "Изменений нет",

    # --- Finding Dialog ---
    "finding.title": "Finding: {type}",
    "finding.value": "Значение",
    "finding.mitre": "MITRE",
    "finding.reasons": "Почему такая уверенность",
    "finding.evidence": "Evidence",
    "finding.no_reasons": "Нет детального разбора (старый детектор или нет причин).",
    "finding.evidence_empty": "Evidence пусто.",
    "finding.close": "Закрыть",

    # --- Contradiction Dialog ---
    "contra.title": "{rule} — {subject}",
    "contra.resolution": "Разрешение",
    "contra.facts": "Факты",
    "contra.causes": "Возможные причины",
    "contra.not_specified": "Не указано.",
    "contra.no_facts": "Фактов нет.",
    "contra.close": "Закрыть",

    # --- Carved Files ---
    "carved.title": "Извлечённые файлы (Carved Files)",
    "carved.warning": "<b>⚠️ ВНИМАНИЕ!</b> Эти файлы извлечены из перехваченного сетевого трафика. Они могут содержать вредоносное ПО.<br>Не открывайте их на рабочей машине без проверки в изолированной среде (Sandbox / VM).",
    "carved.empty": "В этом прогоне файлы не извлекались.",
    "carved.col_sha": "SHA256",
    "carved.col_ext": "Тип",
    "carved.col_size": "Размер",
    "carved.col_uri": "URI",
    "carved.col_status": "Статус",
    "carved.status_saved": "Сохранён на диск",
    "carved.status_meta": "Только метаданные",
    "carved.open_dir": "Открыть папку с файлами",
    "carved.close": "Закрыть",
    "carved.not_saved_title": "Файл не сохранён",
    "carved.not_saved_body": "Тело файла не сохранено на диск. Включите «Сохранять тела файлов на диск» в Настройках → Производительность и запустите анализ заново.",

    # --- Run View & Widgets ---
    "run.drop_title": "Перетащите pcap сюда",
    "run.drop_hint": "или нажмите, чтобы выбрать файл · Ctrl+O",
    "run.open_pcap_dialog": "Открыть pcap",
    "run.multi_pcap": "Открыть несколько pcap для слияния…",
    "run.stop": "Остановить",
    "run.findings": "Находки (Findings)",
    "run.graph": "Граф связей",
    "run.attack_graph": "Граф атаки",
    "run.files": "Файлы",
    "run.what_if": "What-If (Исключить)",
    "run.reset_filter": "Сбросить фильтр",
    "run.no_file": "Файл не выбран.",
    "run.extracting": "Извлечение · {pct}%",
    "run.extracting_speed": "Извлечение · {pct}% · {speed:.1f} МБ/с · ~{remaining:.0f} с",
    "run.detecting": "Детекторы · {done}/{total}",
    "run.detecting_detail": "Детекторы · {done}/{total} · {detail}",
    "run.contradictions": "Противоречия…",
    "run.reports": "Отчёты…",
    "run.cancelled": "Остановлено пользователем",
    "run.done": "Готово · {findings} findings · {contradictions} противоречий · {duration:.1f} сек",
    "run.loaded": "Загружено · {findings} findings · {contradictions} противоречий",
    "run.error": "Ошибка: {msg}",
    "run.multi_warning_title": "Нужно 2+ файла",
    "run.multi_warning_body": "Выбран 1 файл. Для одиночного анализа — перетащите его в зону выше.",
    "run.large_pcap_title": "Большой pcap",
    "run.large_pcap_body": "Файл весит {size:.0f} МБ (порог предупреждения: {limit} МБ).\nАнализ может занять несколько минут и съесть много RAM. Продолжить?",
    "run.large_multi_pcap_body": "Выбрано {count} файлов, суммарно {size:.0f} МБ (порог: {limit} МБ).\nАнализ может занять долго. Продолжить?",
    "error.large_json_title": "Большой JSON-отчёт",
    "error.large_json_body": "Файл весит {size:.0f} МБ (порог предупреждения: {limit} МБ).\nЗагрузка может занять несколько секунд. Продолжить?",

    # --- Findings Table ---
    "find.search_placeholder": "Поиск по value / типу / MITRE…",
    "find.all_types": "Все типы",
    "find.all_conf": "Conf: все",
    "find.host_story_src": "История хоста (src): {ip}",
    "find.host_story_dst": "История хоста (dst): {ip}",

    # --- Panels ---
    "abs.title": "Аномалии / Оборванные сессии",
    "abs.dns": "DNS без ответа",
    "abs.tcp": "TCP без ответа (SYN)",
    "obs.title": "Что видел инструмент",
    "high.title": "Что привлекло внимание",
    "contra.section_title": "Противоречия",
    "contra.card_details": "Подробнее",
    "contra.card_no_facts": "Фактов нет.",

    # --- Graph Dialogs ---
    "graph.title": "Граф связей (Pro)",
    "graph.only_findings": "Только сработки (Findings)",
    "graph.hide_isolated": "Скрыть изолированные узлы",
    "graph.time": "Время: —",
    "graph.tip": "Кликните на узел, чтобы увидеть хронологию.",
    "graph.legend_title": "<b>Легенда:</b>",
    "graph.legend_attacker": "Атакующий / Pivot",
    "graph.legend_victim": "Жертва",
    "graph.legend_internal": "Внутренний",
    "graph.legend_external": "Внешний",
    "graph.legend_subnet": "Подсеть / Другие",
    "graph.legend_finding": "Finding (Сработка)",
    "graph.reset": "Сброс",
    "graph.close": "Закрыть",

    "atk.title": "Граф атаки",
    "atk.paths": "Пути атаки ({count})",
    "atk.legend": "<b>Легенда:</b>",
    "atk.legend_entry": "Вход / Жертва",
    "atk.legend_pivot": "Pivot (Скомпрометирован)",
    "atk.legend_impact": "Impact / C2 (Цель)",
    "atk.legend_lines": "Линии: цвет = фаза kill-chain",
    "atk.legend_zoom": "Колесико мыши — масштаб | Зажать ЛКМ — перемещение",
    "atk.play": "Воспроизвести",
    "atk.pause": "Пауза",
    "atk.details": "Детали пути",
    "atk.export": "<b>Экспорт:</b>",
    "atk.close": "Закрыть",
    "atk.empty": "Нет данных об атаке — findings не образовали связей.",

    "story.title": "История хоста: {ip}",
    "story.timeline": "Хронология для {ip}",
    "story.total": "Всего событий:",
    "story.findings": "Находок:",
    "story.flows": "Потоков:",
    "story.empty": "Событий для этого IP не найдено.",
    "story.close": "Закрыть",

}
