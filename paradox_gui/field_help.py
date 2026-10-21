"""Человеческие описания полей Config для tooltip'ов в GUI.

Словарь FIELD_HELP — ручной. Для полей без описания get_field_help
возвращает generic-текст со ссылкой на config.py.

Словарь SECTION_HELP — описания секций «Настройки». Ключ секции
совпадает с ключом в _SECTIONS в settings_view.py.
"""
from __future__ import annotations

from paradox_gui.i18n import tr

FIELD_HELP: dict[str, str] = {
    # --- Пороги: DGA ---
    "dga_min_label_length":
        "Минимальная длина label (часть домена до первой точки). "
        "Короче — DGA не считаем, слишком много легитимных доменов.",
    "dga_entropy_threshold":
        "Порог энтропии Шеннона для label. Выше — похоже на случайный "
        "набор символов (xg7f2k9vbn).",
    # --- Пороги: NXDOMAIN burst ---
    "nxdomain_burst_threshold":
        "Сколько NXDOMAIN-ответов в окне считать burst'ом.",
    "nxdomain_burst_window_sec":
        "Размер окна в секундах. Проверяется максимум во всех окнах "
        "длиной W от одного src.",
    "nxdomain_burst_min_ratio":
        "Минимальная доля NXDOMAIN среди всех DNS-запросов от src. "
        "Ниже — шум (браузер с редкими опечатками).",
    # --- Пороги: DNS tunneling ---
    "dns_tunneling_min_qname_length":
        "Минимальная длина qname для DNS-туннеля. Короче — это DGA-зона, "
        "не туннель.",
    "dns_tunneling_min_queries":
        "Минимум DNS-запросов к одному базовому домену, чтобы считать "
        "это туннелем.",
    # --- Пороги: brute force ---
    "brute_force_min_flows":
        "Минимум flows для HTTP brute force.",
    "brute_force_max_avg_packets":
        "Максимум среднего числа пакетов на flow. Больше — уже не "
        "брутфорс (браузер грузит сайт).",
    "ftp_brute_force_min_flows":
        "Минимум flows для FTP brute force. FTP-сессия длиннее, "
        "поэтому порог выше.",
    # --- Пороги: beaconing ---
    "beaconing_min_connections":
        "Минимум соединений к одной паре (src, dst, port) для beaconing.",
    "beaconing_min_duration_sec":
        "Минимальная длительность наблюдения. Короткий всплеск — "
        "не C2-heartbeat.",
    "beaconing_max_jitter_ratio":
        "Максимальный jitter = stddev / mean интервалов. Меньше — "
        "ровнее тайминг, сильнее сигнал C2.",
    # --- Пороги: large transfer ---
    "large_transfer_min_bytes":
        "Порог «большой трансфер» в байтах.",
    # --- Пороги: port scan ---
    "port_scan_min_distinct_dsts":
        "Минимум уникальных dst-адресов от одного src для port scan.",
    "port_scan_max_flows_per_dst":
        "Максимум flows на один dst. Больше — это уже работа с сервисом, "
        "не скан.",
    # --- Пороги: reverse asymmetry ---
    "reverse_asymmetry_min_ratio":
        "Во сколько раз большая сторона сессии должна превышать меньшую. "
        "10:1 — аномалия, 25:1 — почти односторонний канал.",
    "reverse_asymmetry_min_total_bytes":
        "Минимальный суммарный объём сессии. Ниже — не смотрим.",
    # --- Brute force ---
    "brute_force_min_unique_src_ports":
        "Минимум уникальных src-портов. Сильный сигнал подбора пароля.",
    "brute_force_uri_ratio_threshold":
        "Доля запросов к login-endpoint от всех. Ниже — не брутфорс.",
    "brute_force_min_rate_flows_per_sec":
        "Минимальная скорость flows/сек. Отсекает медленные легитимные "
        "повторы.",
    "ftp_brute_force_min_unique_src_ports":
        "Минимум уникальных src-портов для FTP brute force.",
    "brute_force_skip_tls_ports":
        "Порты с TLS, где brute force не ищем: там User-Agent не "
        "читается, признак не работает.",
    "login_endpoint_hints":
        "Подстроки URI, по которым определяем login-endpoint: /login, "
        "/admin, /wp-login, …",
    # --- Сеть ---
    "suspicious_ports":
        "Порты, которые считаются подозрительными: 4444, 31337, 1337…",
    "port_scan_excluded_ports":
        "Порты, которые исключаем из port scan — типичный web-трафик.",
    "dc_service_ports":
        "Порты domain controller: Kerberos, LDAP, SMB. Их наличие + "
        "много flows отличает DC от обычного сервера.",
    "lateral_movement_ports":
        "Порты lateral movement: SMB, RDP, WinRM, MSRPC.",
    "beaconing_mail_polling_ports":
        "POP3/IMAP-порты. Почтовый клиент дёргает ящик по таймеру — "
        "это не C2-beaconing.",
    "private_networks":
        "Префиксы приватных сетей. Используется для классификации "
        "dst как «внутренний» или «внешний».",
    # --- Производительность ---
    "tcp_reassembly_enabled":
        "Склеивать TCP-сегменты в потоки. Даёт полные ClientHello и "
        "HTTP body, но расходует память.",
    "tcp_reassembly_max_bytes_per_flow":
        "Лимит памяти на один flow при reassembly.",
    "tcp_reassembly_max_total_bytes":
        "Общий лимит памяти на reassembly. Защита от гигабайтных pcap.",
    "file_carve_enabled":
        "Извлекать метаданные payload'ов (sha256, тип, размер). "
        "Без записи содержимого на диск.",
    "file_carve_write_body":
        "Писать тела файлов на диск как <sha256>.bin. Осторожно: "
        "много места.",
    "file_carve_min_size":
        "Минимальный размер payload для file carve.",
    "file_carve_max_size":
        "Максимальный размер payload для file carve.",
    "entities_top_n":
        "Сколько top-сущностей (по активности) показывать в отчёте.",
    "flow_report_top_n":
        "Сколько top-flow'ов по байтам включать в flow report.",
    # --- Allowlist ---
    "beaconing_allowlist_suffixes":
        "Суффиксы SNI/Host, для которых beaconing не считаем: "
        "analytics, CDN, cloud.",
    "beaconing_allowlist_ips":
        "Точные IP без SNI, для которых beaconing не считаем.",
    "dns_tunneling_allowlist":
        "DoH-домены: dns.google, cloudflare-dns.com. Не считать "
        "туннелем.",
    "sni_mismatch_allowlist":
        "Известные проверочные домены (OCSP, CRL, DoH), у которых "
        "SNI ≠ Host штатно.",
    "large_transfer_excluded_hosts":
        "Хосты, для которых большие трансферы норма: обновления "
        "Windows, Apple.",
    "large_transfer_excluded_user_agents":
        "User-Agent'ы, для которых большие трансферы норма: BITS, "
        "CryptoAPI, Delivery Optimization.",
    # --- DGA ---
    "dga_allowlist":
        "Итоговый allowlist DGA = extra + cloud tunnel + ip-check "
        "сервисы. Удаление элемента означает, что DGA начнёт "
        "ругаться на этот домен.",
    # --- Отчёты ---
    "output_dir":
        "Каталог для отчётов и артефактов. Создаётся при применении.",
    # --- Threat Intel ---
    "enrichment_enabled_providers":
        "Какие провайдеры использовать. Без ключа: shodan_internetdb, "
        "greynoise, alienvault_otx, urlscan. С ключом: abuseipdb, "
        "virustotal. С ABUSECH_AUTH_KEY: urlhaus, malwarebazaar, threatfox.",
    "enrichment_cache_ttl_days":
        "TTL кэша обогащения в днях.",
    "enrichment_cache_path":
        "Путь к SQLite-файлу кэша обогащения.",
    "enrichment_max_iocs":
        "Сколько IOC обогащать за один прогон.",
}


SECTION_HELP: dict[str, str] = {
    "general":
        "Общие настройки приложения. Пока заглушка.",
    "thresholds":
        "Пороги детекторов. Больше значение — меньше срабатываний, "
        "но выше требования к сигналу. Профиль сверху — готовый набор "
        "порогов под задачу.",
    "detectors":
        "Включение и выключение детекторов. Снятая галочка = детектор "
        "не запускается в следующем прогоне.",
    "contradictions":
        "Правила проверки согласованности между слоями данных: "
        "DNS vs SNI, MAC vs IP, роль vs поведение. Отключение убирает "
        "проверку.",
    "allowlist":
        "Белые списки. Совпадение элемента убирает кандидата из "
        "findings.",
    "dga":
        "Итоговый allowlist для детектора DGA.",
    "brute":
        "Как детектор отличает подбор пароля от обычного трафика.",
    "network":
        "Списки портов и префиксов сетей, на которые опираются "
        "несколько детекторов.",
    "reports":
        "Куда ядро складывает артефакты: отчёты, кэш обогащения, "
        "carved files.",
    "threatintel":
        "Обогащение IOC. API-ключи хранятся в системном keyring, "
        "а не в settings.json.",
    "perf":
        "Компромисс память/полнота. Отключение TCP-склейки и карвинга "
        "ускоряет прогон на больших pcap, но теряет часть findings.",
}


# Соответствие заголовка секции (заголовок в _make_header) её ключу.
SECTION_BY_TITLE: dict[str, str] = {
    "Пороги": "thresholds",
    "Детекторы": "detectors",
    "ContradictionDetector": "contradictions",
    "Allowlist": "allowlist",
    "DGA": "dga",
    "Brute force": "brute",
    "Сеть": "network",
    "Отчёты": "reports",
    "Threat Intel": "threatintel",
    "Производительность": "perf",
    "Общие": "general",
}


def get_field_help(key: str) -> str:
    translated = tr(f"settings.help.{key}")
    if translated != f"settings.help.{key}":
        return translated
    text = FIELD_HELP.get(key)
    if text:
        return text
    return tr("settings.help.fallback", key=key)


def get_section_help(key: str) -> str:
    translated = tr(f"settings.section_help.{key}")
    if translated != f"settings.section_help.{key}":
        return translated
    return SECTION_HELP.get(key, "")
