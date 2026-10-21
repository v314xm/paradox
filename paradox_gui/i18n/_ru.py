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
    "settings.help.fallback": "Параметр «{key}» из Config ядра. См. paradox/config.py.",

}
