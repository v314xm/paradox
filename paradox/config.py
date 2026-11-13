from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import NamedTuple


def _frozen(*items: str) -> frozenset[str]:
    return frozenset(items)


class _ValidationRule(NamedTuple):
    field: str
    valid: Callable[[object], bool]
    message: str


def _positive(value: float) -> bool:
    return value > 0


def _non_negative(value: float) -> bool:
    return value >= 0


def _ratio(value: float) -> bool:
    return 0.0 < value <= 1.0


def _at_least_two(value: int) -> bool:
    return value >= 2


def _non_empty(value: object) -> bool:
    return bool(value)


def _non_blank(value: object) -> bool:
    return bool(str(value).strip())


def _ports_in_range(value: object) -> bool:
    return all(1 <= p <= 65535 for p in value)


_VALIDATION_RULES: tuple[_ValidationRule, ...] = (
    _ValidationRule("file_carve_min_size", _positive,
                    "file_carve_min_size must be > 0"),
    _ValidationRule("file_carve_max_size", _positive,
                    "file_carve_max_size must be > 0"),
    _ValidationRule("command_injection_min_patterns", _positive,
                    "command_injection_min_patterns must be > 0"),
    _ValidationRule("command_injection_aggregate_min", _positive,
                    "command_injection_aggregate_min must be > 0"),
    _ValidationRule("tcp_reassembly_max_bytes_per_flow", _positive,
                    "tcp_reassembly_max_bytes_per_flow must be > 0"),
    _ValidationRule("tcp_reassembly_max_total_bytes", _positive,
                    "tcp_reassembly_max_total_bytes must be > 0"),
    _ValidationRule("enrichment_cache_ttl_days", _positive,
                    "enrichment_cache_ttl_days must be > 0"),
    _ValidationRule("enrichment_max_iocs", _positive,
                    "enrichment_max_iocs must be > 0"),
    _ValidationRule("dns_tunneling_min_qname_length", _positive,
                    "dns_tunneling_min_qname_length must be > 0"),
    _ValidationRule("dns_tunneling_min_long_qnames", _positive,
                    "dns_tunneling_min_long_qnames must be > 0"),
    _ValidationRule("dns_tunneling_min_queries", _positive,
                    "dns_tunneling_min_queries must be > 0"),
    _ValidationRule("beaconing_min_connections", _positive,
                    "beaconing_min_connections must be > 0"),
    _ValidationRule("beaconing_min_duration_sec", _positive,
                    "beaconing_min_duration_sec must be > 0"),
    _ValidationRule("beaconing_max_jitter_ratio", _ratio,
                    "beaconing_max_jitter_ratio must be in (0, 1]"),
    _ValidationRule("beaconing_max_avg_bytes", _positive,
                    "beaconing_max_avg_bytes must be > 0"),
    _ValidationRule("beaconing_max_flows_per_minute", _positive,
                    "beaconing_max_flows_per_minute must be > 0"),
    _ValidationRule("beaconing_payload_stddev_ratio_max", _non_negative,
                    "beaconing_payload_stddev_ratio_max must be >= 0"),
    _ValidationRule("beaconing_mail_polling_ports", _non_empty,
                    "beaconing_mail_polling_ports must not be empty"),
    _ValidationRule("beaconing_mail_polling_ports", _ports_in_range,
                    "beaconing_mail_polling_ports must be in range 1..65535"),
    _ValidationRule("beaconing_slow_min_connections", _at_least_two,
                    "beaconing_slow_min_connections must be >= 2"),
    _ValidationRule("beaconing_slow_min_duration_sec", _positive,
                    "beaconing_slow_min_duration_sec must be > 0"),
    _ValidationRule("beaconing_slow_max_jitter_ratio", _ratio,
                    "beaconing_slow_max_jitter_ratio must be in (0, 1]"),
    _ValidationRule("beaconing_slow_max_flows_per_minute", _positive,
                    "beaconing_slow_max_flows_per_minute must be > 0"),
    _ValidationRule("http_binary_upload_min_posts", _positive,
                    "http_binary_upload_min_posts must be > 0"),
    _ValidationRule("http_binary_upload_min_body_bytes", _positive,
                    "http_binary_upload_min_body_bytes must be > 0"),
    _ValidationRule("command_injection_min_printable_ratio", _ratio,
                    "command_injection_min_printable_ratio must be in (0, 1]"),
    _ValidationRule("http_body_max_decoded_bytes", _positive,
                    "http_body_max_decoded_bytes must be > 0"),
    _ValidationRule("payload_excerpt_bytes", _positive,
                    "payload_excerpt_bytes must be > 0"),
    _ValidationRule("payload_multipart_file_bytes", _positive,
                    "payload_multipart_file_bytes must be > 0"),
    _ValidationRule("payload_multipart_max_parts", _positive,
                    "payload_multipart_max_parts must be > 0"),
    _ValidationRule("payload_multipart_total_bytes", _positive,
                    "payload_multipart_total_bytes must be > 0"),
    _ValidationRule("http_object_body_limit", _positive,
                    "http_object_body_limit must be > 0"),
    _ValidationRule("http_object_max_messages_per_stream", _positive,
                    "http_object_max_messages_per_stream must be > 0"),
    _ValidationRule("ftp_brute_force_min_flows", _positive,
                    "ftp_brute_force_min_flows must be > 0"),
    _ValidationRule("ssh_brute_force_min_flows", _positive,
                    "ssh_brute_force_min_flows must be > 0"),
    _ValidationRule("smtp_spam_min_recipients", _positive,
                    "smtp_spam_min_recipients must be > 0"),
    _ValidationRule("ftp_brute_force_min_unique_src_ports", _positive,
                    "ftp_brute_force_min_unique_src_ports must be > 0"),
    _ValidationRule("large_transfer_min_bytes", _positive,
                    "large_transfer_min_bytes must be > 0"),
    _ValidationRule("rare_external_ip_max_connections", _positive,
                    "rare_external_ip_max_connections must be > 0"),
    _ValidationRule("rare_external_ip_excluded_ports", _ports_in_range,
                    "rare_external_ip_excluded_ports must be in range 1..65535"),
    _ValidationRule("encoded_payload_min_value_len", _positive,
                    "encoded_payload_min_value_len must be > 0"),
    _ValidationRule("encoded_payload_max_decoded_len", _positive,
                    "encoded_payload_max_decoded_len must be > 0"),
    _ValidationRule("long_connection_min_duration_sec", _positive,
                    "long_connection_min_duration_sec must be > 0"),
    _ValidationRule("long_connection_min_packets", _positive,
                    "long_connection_min_packets must be > 0"),
    _ValidationRule("long_connection_excluded_ports", _ports_in_range,
                    "long_connection_excluded_ports must be in range 1..65535"),
    _ValidationRule("lateral_movement_min_flows_port_only", _positive,
                    "lateral_movement_min_flows_port_only must be > 0"),
    _ValidationRule("lateral_movement_ports", _non_empty,
                    "lateral_movement_ports must not be empty"),
    _ValidationRule("dga_entropy_threshold", _positive,
                    "dga_entropy_threshold must be > 0"),
    _ValidationRule("dga_min_label_length", _positive,
                    "dga_min_label_length must be > 0"),
    _ValidationRule("nxdomain_burst_threshold", _positive,
                    "nxdomain_burst_threshold must be > 0"),
    _ValidationRule("nxdomain_burst_window_sec", _positive,
                    "nxdomain_burst_window_sec must be > 0"),
    _ValidationRule("nxdomain_burst_min_ratio", _ratio,
                    "nxdomain_burst_min_ratio must be in (0, 1]"),
    _ValidationRule("typosquatting_levenshtein_threshold", _non_negative,
                    "typosquatting_levenshtein_threshold must be >= 0"),
    _ValidationRule("sni_mismatch_min_flows", _positive,
                    "sni_mismatch_min_flows must be > 0"),
    _ValidationRule("brute_force_min_flows", _positive,
                    "brute_force_min_flows must be > 0"),
    _ValidationRule("brute_force_max_avg_packets", _positive,
                    "brute_force_max_avg_packets must be > 0"),
    _ValidationRule("brute_force_min_unique_src_ports", _positive,
                    "brute_force_min_unique_src_ports must be > 0"),
    _ValidationRule("brute_force_uri_ratio_threshold", _ratio,
                    "brute_force_uri_ratio_threshold must be in (0, 1]"),
    _ValidationRule("brute_force_min_rate_flows_per_sec", _positive,
                    "brute_force_min_rate_flows_per_sec must be > 0"),
    _ValidationRule("bruteforce_success_uri_hints", _non_empty,
                    "bruteforce_success_uri_hints must not be empty"),
    _ValidationRule("dc_min_service_flows", _positive,
                    "dc_min_service_flows must be > 0"),
    _ValidationRule("dc_min_unique_srcs", _positive,
                    "dc_min_unique_srcs must be > 0"),
    _ValidationRule("entities_top_n", _positive,
                    "entities_top_n must be > 0"),
    _ValidationRule("gateway_min_flows", _positive,
                    "gateway_min_flows must be > 0"),
    _ValidationRule("gateway_min_unique_dsts", _positive,
                    "gateway_min_unique_dsts must be > 0"),
    _ValidationRule("flow_report_top_n", _positive,
                    "flow_report_top_n must be > 0"),
    _ValidationRule("absence_top_n", _positive,
                    "absence_top_n must be > 0"),
    _ValidationRule("plugins_dir", _non_blank,
                    "plugins_dir must not be empty"),
    _ValidationRule("web_scanner_min_distinct_paths", _positive,
                    "web_scanner_min_distinct_paths must be > 0"),
    _ValidationRule("port_scan_min_distinct_dsts", _positive,
                    "port_scan_min_distinct_dsts must be > 0"),
    _ValidationRule("port_scan_max_flows_per_dst", _positive,
                    "port_scan_max_flows_per_dst must be > 0"),
    _ValidationRule("port_scan_excluded_ports", _non_empty,
                    "port_scan_excluded_ports must not be empty"),
    _ValidationRule("port_scan_excluded_ports", _ports_in_range,
                    "port_scan_excluded_ports must be in range 1..65535"),
    _ValidationRule("suspicious_ports", _non_empty,
                    "suspicious_ports must not be empty"),
    _ValidationRule("dc_service_ports", _non_empty,
                    "dc_service_ports must not be empty"),
    _ValidationRule("suspicious_ports", _ports_in_range,
                    "suspicious_ports must be in range 1..65535"),
    _ValidationRule("dc_service_ports", _ports_in_range,
                    "dc_service_ports must be in range 1..65535"),
    _ValidationRule("behavioral_contamination", _ratio,
                    "behavioral_contamination must be in (0, 1]"),
    _ValidationRule("behavioral_confidence_min", _ratio,
                    "behavioral_confidence_min must be in (0, 1]"),
    _ValidationRule("behavioral_min_flows", _positive,
                    "behavioral_min_flows must be > 0"),
    _ValidationRule("behavioral_min_hosts", _positive,
                    "behavioral_min_hosts must be > 0"),
    _ValidationRule("behavioral_max_findings", _positive,
                    "behavioral_max_findings must be > 0"),
    _ValidationRule("behavioral_seed", _non_negative,
                    "behavioral_seed must be >= 0"),
    _ValidationRule("role_scanner_min_targets", _positive,
                    "role_scanner_min_targets must be > 0"),
    _ValidationRule("role_scanner_min_ports", _positive,
                    "role_scanner_min_ports must be > 0"),
    _ValidationRule("role_server_min_bytes", _non_negative,
                    "role_server_min_bytes must be >= 0"),
)


@dataclass(frozen=True)
class Config:
    # --- cloud tunnel domains (источник правды) ---
    cloud_tunnel_domains: frozenset[str] = field(default_factory=lambda: _frozen(
        "trycloudflare.com",
        "ngrok.io",
        "ngrok-free.app",
        "serveo.net",
        "localtunnel.me",
        "lhr.life",
        "pinggy.io",
    ))

    # --- ip check services (источник правды) ---
    ip_check_services: frozenset[str] = field(default_factory=lambda: _frozen(
        "ip-api.com",
        "ipinfo.io",
        "ifconfig.me",
        "icanhazip.com",
        "api.ipify.org",
        "ipify.org",
        "myexternalip.com",
        "checkip.amazonaws.com",
    ))
    # Известные стабильные IP сервисов проверки внешнего IP.
    # Mapping IP → каноническое имя сервиса. Нужно для случая, когда
    # клиент стучится напрямую по IP без DNS (или DNS-запрос в другом
    # файле захвата). Если IP совпал — используем имя сервиса как value,
    # чтобы finding'и от DNS/SNI/direct_ip сливались в один.
    ip_check_service_ips: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({
            "208.95.112.1": "ip-api.com",
            "208.95.112.2": "ip-api.com",
            "34.117.59.81": "ifconfig.me",
            "34.160.111.145": "ifconfig.me",
        }),
    )

    # --- JA3 fingerprinting ---
    # Известные malware/pentest-фреймворки по JA3-хешу.
    # Mapping JA3 → человекочитаемое имя для evidence.
    #
    # Источники: abuse.ch SSL Blacklist, Salesforce JA3,
    # публичные отчёты по malware.
    #
    # ВАЖНО: python-requests / urllib / go-http-client — это
    # инструменты разработчика и аналитика, а не malware.
    # Держим их отдельно в ja3_known_tools, чтобы не FP-ить
    # на любом легитимном скрипте в сети.
    ja3_known_malware: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({
            # Cobalt Strike
            "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (default)",
            "72a589da586844d7f0818ce684948eea": "Cobalt Strike (variant 1)",
            "8e01a8b1be8e3a4b3be0f7e5b3adceba": "Cobalt Strike (variant 2)",
            # Anonymizers / malware
            "e7d705a3286e19ea42f587b344ee6865": "Tor client",
            "6734f37431670b3ab4292b8f60f29984": "Dridex",
            "51c64c77e60f3980eea90869b68c58a8": "Trickbot",
            "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet",
        }),
    )
    # Известные инструменты (не malware). Findings по ним —
    # информационные, confidence ниже, чем у malware. Позволяет
    # видеть «в сети есть питон-скрипт», не путая с C2.
    ja3_known_tools: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({
            "3b5074b1b5d032e5620f69f9f700ff0e": "python-requests (default)",
            "579ccef312d18482fc42e2b822ca2430": "python-urllib",
            "894cc2ab0f7e28b3e0c32fcbd1a3a2a8": "go-http-client",
        }),
    )

    # JA3S (ServerHello fingerprint). Дополняет клиентский JA3.
    # Публичных баз JA3S меньше, чем JA3, поэтому по умолчанию пусто:
    # детектор молчит, но flow.ja3s виден в отчёте для ручного анализа.
    # Пользователь добавляет свои хеши после валидации на реальных pcap.
    ja3s_known_malware: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({}),
    )

    # --- command injection ---
    # Паттерны RCE в HTTP URI/body. Два уровня confidence.
    #
    # high — почти наверняка RCE (языковые конструкции)
    command_injection_patterns_high: frozenset[str] = field(
        default_factory=lambda: _frozen(
            # Lua (OpenResty, Nginx-модули)
            "io.popen", "os.execute",
            # PHP
            "system(", "exec(", "shell_exec(", "pass" "thru(",
            "popen(", "proc_open(", "pcntl_exec(",
            # Python
            "os.system(", "subprocess.popen(", "subprocess.run(",
            "__import__('os').system",
            # Ruby
            "io.popen", "kernel.exec",
            # Node
            "child_process", "require('child_process')",
            # Java
            "runtime.getruntime().exec",
        ),
    )
    # medium — подозрительно в контексте, но может быть легитимно
    command_injection_patterns_medium: frozenset[str] = field(
        default_factory=lambda: _frozen(
            # Shell-синтаксис
            "$(", "`", "|nc ", "| nc ", "&&",
            # Утилиты
            "cmd.exe", "/bin/sh", "/bin/bash", "/bin/zsh",
            "powershell", "pwsh",
            "wget http", "curl http", "curl -",
            "whoami", "uname -a", "id;", "base64 -d",
        ),
    )
    # Порог: один finding на (src_ip, uri).
    command_injection_min_patterns: int = 1
    # Агрегация: если с одного (src_ip, dst_ip) набралось
    # >= этого числа hit'ов — один finding с count вместо N.
    # В CTF 2015-03-17 было 32 hit'а с одного src на один endpoint.
    command_injection_aggregate_min: int = 5
    # Body без content-type сканируем, только если он похож на текст.
    # gzip/бинарь даёт ложные совпадения на "$(" и "`" в сжатых байтах.
    command_injection_min_printable_ratio: float = 0.85
    # Распаковка gzip/deflate для поиска паттернов. Лимит защищает
    # от zip-бомбы: больше этого объёма не распаковываем.
    http_body_decompress: bool = True
    http_body_max_decoded_bytes: int = 8 * 1024 * 1024
    # Выдержка тела, на котором сработал детектор инъекций/шеллов.
    # Нужна вкладке «Код инжекта»: показать код, а не только паттерны.
    # В отчёт кладётся base64 — антивирус не должен ловить сигнатуры
    # шеллов в JSON-файле отчёта.
    payload_excerpt_enabled: bool = True
    payload_excerpt_bytes: int = 64 * 1024
    # multipart/form-data: поле и файл разбираются отдельно, чтобы
    # файл, начинающийся за границей общей выдержки, всё равно был
    # виден в «Коде инжекта». Бюджет ограничен, чтобы отчёт не рос.
    payload_multipart_enabled: bool = True
    payload_multipart_file_bytes: int = 64 * 1024
    payload_multipart_max_parts: int = 32
    payload_multipart_total_bytes: int = 256 * 1024
    # Искать IOC в тексте выдержек и отдавать их в «Обогащение» и
    # IOC-отчёт. Иначе домен из тела виден только в «Коде инжекта».
    payload_ioc_extraction: bool = True

    # --- binary HTTP upload (exfil / C2) ---
    # Много POST'ов с бинарным телом на внешний хост — типовой канал
    # RAT/stealer'а. Легитимные машины так делают редко, поэтому
    # требуем серию, а не одиночный запрос.
    http_binary_upload_min_posts: int = 3
    http_binary_upload_min_body_bytes: int = 1024
    # content-type, которые считаем текстом даже без charset.
    # Используется и command_injection (не искать shell в бинаре),
    # и http_binary_upload (не считать такой POST бинарным).
    http_text_content_types: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "application/json",
            "application/xml",
            "application/soap+xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/javascript",
            "application/graphql",
        ),
    )
    # Разбор HTTP-объектов из склеенных потоков: лимит тела
    # и максимум сообщений в одном keep-alive-соединении.
    http_object_body_limit: int = 1 * 1024 * 1024
    http_object_max_messages_per_stream: int = 200

    # --- HTTP/2 и TLS ---
    # h2c разбирается всегда; h2 поверх TLS — только если задан
    # keylog-файл от клиента/сервера (SSLKEYLOGFILE). Файл содержит
    # секреты сессий: обращаться с ним как с чувствительными данными.
    http2_enabled: bool = True
    tls_keylog_path: str | None = None
    # Хосты, которым бинарные POST'ы — норма (обновления, телеметрия).
    http_binary_upload_allowlist_suffixes: frozenset[str] = field(
        default_factory=frozenset,
    )
    # Бинарные content-type служебных протоколов: OCSP-запросы
    # выглядят как exfil, но это проверка отзыва сертификата.
    http_binary_upload_ignored_content_types: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "application/ocsp-request",
            "application/x-ocsp-request",
        ),
    )

    # --- file carve ---
    # Метаданные payload'ов — всегда (безопасно, без записи на диск).
    file_carve_enabled: bool = True
    yara_rules_path: str | None = None
    # Содержимое body на диск — по умолчанию ВЫКЛЮЧЕНО.
    # При включении сохраняется как <sha256>.bin, НЕ как .exe/.ps1.
    file_carve_write_body: bool = False
    file_carve_min_size: int = 64
    file_carve_max_size: int = 50 * 1024 * 1024

    # --- DGA ---
    dga_entropy_threshold: float = 3.5
    dga_min_label_length: int = 12
    _dga_allowlist_extra: frozenset[str] = field(default_factory=lambda: _frozen(
        "amazonaws.com",
        "cloudfront.net",
        "azureedge.net",
        "akamaiedge.net",
        "googleusercontent.com",
        "windowsupdate.com",
        "cloudapp.azure.com",
        # Cisco Umbrella / OpenDNS
        "footprintdns.com",
        "opendns.com",
        "stackoverflow.com",
        "stackexchange.com",
        "serverfault.com",
        "superuser.com",
        "askubuntu.com",
        # Live Messenger — поддомены с цифрами дают высокую энтропию
        "messenger.live.com",
        # Легитимные блоги и сервисы с длинными именами
        "acuityplatform.com",
        "sourceforge.net",
        "windowsteamblog.com",
        "mysqlperformanceblog.com",
        "hotpropertydesigns.com",
        "thrivinglifestylez.com",
        "hdwallpapersfactory.com",
        "migratoryspecies.org",
    ))
    dga_allowlist: frozenset[str] = field(default_factory=frozenset, init=False)

    # --- suspicious ports ---
    suspicious_ports: frozenset[int] = field(default_factory=lambda: frozenset({

        22,     # SSH (наружу)
        23,     # Telnet
        4444,   # Metasploit default
        1337,   # leet
        31337,  # Back Orifice / leet
        8080,   # alt-http
        8443,   # alt-https
        12132,  # STRRAT из примеров
    }))

    private_networks: tuple[str, ...] = (
        # IPv4
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "127.",
        "169.254.",
        "224.", "239.",
        "255.255.255.255",
        # IPv6
        "fc", "fd",       # Unique Local Address (ULA)
        "fe80",           # Link-local
        "::1",            # Loopback
    )

    # --- port scan ---
    port_scan_min_distinct_dsts: int = 10
    port_scan_max_flows_per_dst: int = 3
    port_scan_excluded_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({80, 443}),
    )

    # --- TCP reassembly ---
    # Склейка TCP-сегментов в потоки по (src, dst, src_port, dst_port).
    # Даёт полные ClientHello/ServerHello, HTTP body и Kerberos-сообщения,
    # которые не влезают в первый сегмент.
    #
    # Ограничения памяти:
    # - per flow: 1 МБ. Больше для HTTP body всё равно не нужно.
    # - total: 200 МБ. Защита от гигабайтных захватов.
    tcp_reassembly_enabled: bool = True
    tcp_reassembly_max_bytes_per_flow: int = 1024 * 1024
    tcp_reassembly_max_total_bytes: int = 200 * 1024 * 1024

    # --- beaconing ---
    # C2-heartbeat: регулярные обращения к одной паре (src, dst, port).
    # Признаки: N соединений, длительность, малый jitter (stddev/mean),
    # маленький размер соединения.
    #
    # История порогов:
    #   0.6.0: min=10, duration=300, jitter<0.2, bytes<5000
    #          → 310 FP на FIN-2015 (analytics/CDN дёргаются по таймеру).
    #   0.7.0: min=20, duration=600, jitter<0.1, +allowlist SNI/Host,
    #          +payload stddev, +rate check, +skip internal dst,
    #          +multi-tenant filter (shared CDN), +mail-port filter.
    #
    # Что такое multi-tenant filter:
    #   Если через (src, dst_ip, dst_port) идёт > 1 уникального SNI/Host —
    #   это shared CDN/edge (Akamai, Cloudflare). Chrome открывает
    #   десятки соединений к одному edge, но каждый — к разному домену.
    #   C2 использует ОДИН домен. Это самый сильный сигнал против
    #   CDN-шума, и он не требует хардкода IP-префиксов.
    #
    # Что такое mail polling:
    #   POP3/IMAP клиенты поллят ящик каждые 5–15 минут по таймеру.
    #   jitter < 0.1, payload const — идеальный ложный beacon.
    #   SMTP (25/465/587) НЕ исключаем: бывает SMTP-туннель от malware.
    beaconing_min_connections: int = 20
    beaconing_min_duration_sec: int = 600
    beaconing_max_jitter_ratio: float = 0.1
    beaconing_max_avg_bytes: int = 5000
    beaconing_max_flows_per_minute: float = 5.0
    beaconing_payload_stddev_ratio_max: float = 0.5
    beaconing_skip_internal_dst: bool = True

    # Медленный beacon (sleep > часа): соединений мало, но горизонт
    # длинный. Обычный путь требует 20 соединений — такой C2 за
    # 20 часов в коротком захвате не наберёт. Второй, «slow», путь
    # смотрит на регулярность при малом числе соединений.
    beaconing_slow_min_connections: int = 3
    beaconing_slow_min_duration_sec: int = 3600
    beaconing_slow_max_jitter_ratio: float = 0.15
    beaconing_slow_max_flows_per_minute: float = 0.2

    # POP3/IMAP. Клиент дёргает ящик по таймеру — design, не C2.
    beaconing_mail_polling_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({
            110,  # POP3
            143,  # IMAP
            993,  # IMAPS
            995,  # POP3S
        }),
    )

    # Allowlist по SNI/HTTP Host (endswith). Analytics, CDN, cloud.
    # Срабатывает, когда у группы ЕДИНСТВЕННЫЙ SNI/Host из списка.
    # Если SNI/Host больше одного — сработает multi-tenant filter
    # раньше этого allowlist'а.
    beaconing_allowlist_suffixes: frozenset[str] = field(
        default_factory=lambda: _frozen(
            # Analytics / telemetry
            "google-analytics.com",
            "analytics.google.com",
            "googletagmanager.com",
            "googlesyndication.com",
            "googleadservices.com",
            "doubleclick.net",
            "gstatic.com",
            "googleusercontent.com",
            "googlevideo.com",
            "facebook.com",
            "fbcdn.net",
            "scorecardresearch.com",
            "quantserve.com",
            "adsrvr.org",
            "adnxs.com",
            "criteo.com",
            "criteo.net",
            "casalemedia.com",
            "rubiconproject.com",
            "pubmatic.com",
            "openx.net",
            "yimg.com",
            "licdn.com",
            # Browser background updates: Chrome ходит за базами Safe
            # Browsing по расписанию, с медленным режимом это давало
            # ложный beaconing на чистом захвате (FIRST-2015).
            "safebrowsing-cache.google.com",
            "safebrowsing.googleapis.com",
            "safebrowsing.google.com",
            # Microsoft / Skype
            "skypeassets.com",
            "skype.com",
            "msn.com",
            "rad.msn.com",
            # CDN / cloud
            "cloudflare.com",
            "cloudflare-dns.com",
            "cloudfront.net",
            "akamai.net",
            "akamaized.net",
            "akamaihd.net",
            "akamaiedge.net",
            "fastly.net",
            "fastlylb.net",
            "edgekey.net",
            "edgesuite.net",
            "llnwd.net",
            "amazonaws.com",
            "azure.com",
            "azureedge.net",
            "windowsupdate.com",
            "download.microsoft.com",
            "update.microsoft.com",
            "swcdn.apple.com",
            "swdist.apple.com",
            "mesu.apple.com",
            "gdmf.apple.com",
            "apple.com",
            "microsoft.com",
            "msedge.net",
            "smartscreen.microsoft.com",
        ),
    )

    # Точечные IP для skip (analytics без SNI, специфика окружения).
    # Основной механизм — multi-tenant filter, а не этот список.
    beaconing_allowlist_ips: frozenset[str] = field(
        default_factory=frozenset,
    )

    # --- DNS tunneling ---
    # Классический признак: длинные уникальные поддомены под одним
    # базовым доменом. Данные кодируются в qname (base64, hex).
    # Пример: aGVsbG8gd29ybGQK.dns.attacker.com
    #
    # Отличие от DGA:
    #   - DGA — короткие поддомены (10-15 символов), много разных
    #   - Tunneling — длинные (>50), тоже много
    # Требуем именно длинные — DGA отсеется автоматически.
    dns_tunneling_min_qname_length: int = 50
    dns_tunneling_min_long_qnames: int = 20
    dns_tunneling_min_queries: int = 50
    # Известные DNS-over-HTTPS, whitelist. Не считаются туннелем.
    dns_tunneling_allowlist: frozenset[str] = field(default_factory=lambda: _frozen(
        "dns.google",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
    ))

    # --- large transfer ---
    large_transfer_min_bytes: int = 100 * 1024 * 1024
    large_transfer_include_reverse: bool = True
    # Хосты и UA, для которых большие трансферы — норма. Загрузка
    # обновлений Windows через BITS, апдейты macOS. Ищем подстроку
    # в http_host или user_agent.
    large_transfer_excluded_hosts: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "windowsupdate.com",
            "download.microsoft.com",
            "update.microsoft.com",
            "swdist.apple.com",
            "swcdn.apple.com",
            "mesu.apple.com",
            "gdmf.apple.com",
        ),
    )
    large_transfer_excluded_user_agents: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "Microsoft BITS",
            "Microsoft-CryptoAPI",
            "Microsoft-Delivery-Optimization",
        ),
    )

    # --- rare external ip ---
    # Внутренний клиент открыл 1–2 соединения к внешнему адресу,
    # которого нет в DNS-ответах этого захвата и который не назван
    # ни через SNI, ни через HTTP Host.
    #
    # Наивный порог «1–2 flow к внешнему IP» даёт 52 кандидата на
    # 2025-06-13 и 36 на FIRST-2015 — все легитимные сервисы.
    # Поэтому сравнение с dns_answers_by_ip обязательно, а не
    # опционально: без него правило непригодно.
    rare_external_ip_max_connections: int = 2
    rare_external_ip_allowlist_ips: frozenset[str] = field(
        default_factory=frozenset,
    )
    # Инфраструктурные порты: обращения к ним по IP — норма
    # (резолверы, NTP, multicast-службы, DoT).
    rare_external_ip_excluded_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({
            53,     # DNS
            67, 68,  # DHCP
            123,    # NTP
            137, 138,  # NetBIOS
            853,    # DNS-over-TLS
            1900,   # SSDP
            3702,   # WS-Discovery
            5353,   # mDNS
            5355,   # LLMNR
        }),
    )

    # --- encoded payload ---
    # Значение query/тела формы, которое декодируется из base64/hex в
    # URL или домен: так прячут адрес C2, редирект или сайт-источник
    # при телеметрии. Пример: site=aHR0cHM6Ly9taW5maW4uc2FtcmVnaW9uLnJ1
    # Порог по длине отсекает короткие токены, которые тоже иногда
    # выглядят как base64.
    encoded_payload_min_value_len: int = 16
    encoded_payload_max_decoded_len: int = 512

    # --- long connections ---
    # TCP-сессия внутренний→внешний, установленная в захвате (виден
    # SYN), которая живёт дольше получаса и не представилась ни SNI,
    # ни HTTP Host. Похоже на keepalive C2 или reverse shell в одном
    # соединении. Объём оценивают large_transfer и reverse_asymmetry,
    # здесь важна только длительность.
    long_connection_min_duration_sec: int = 1800
    long_connection_min_packets: int = 5
    # Порты служб, для которых долгая сессия — штатный режим:
    # SSH, почта (IDLE), VPN, БД, RDP/VNC, локальные прокси.
    long_connection_excluded_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({
            22,     # SSH
            25, 110, 143, 465, 587, 993, 995,  # почта
            1194, 1723,          # OpenVPN / PPTP
            3306, 5432, 6379,    # БД
            3389, 5900,          # RDP / VNC
            8080, 8443,          # локальные прокси
        }),
    )
    # Имена, для которых долгое соединение — норма (push-каналы,
    # обновления, CDN). Проверка по суффиксу SNI/Host.
    long_connection_allowlist_suffixes: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "windows.com",
            "wns.windows.com",
            "microsoft.com",
            "msedge.net",
            "apple.com",
            "icloud.com",
            "google.com",
            "googleapis.com",
            "gstatic.com",
            "cloudflare.com",
            "akamai.net",
            "akamaized.net",
            "amazonaws.com",
        ),
    )

    # --- port service mismatch ---
    # Какие протоколы разрешены на порту. Ключ — порт, значение —
    # набор допустимых протоколов. Протокол детектируется в facts.py:
    #   "tls"  — ClientHello (есть ja3/sni)
    #   "http" — HTTP-метод в payload
    #
    # Порты НЕ в этом словаре — вне зоны проверки. Так мы не трогаем
    # нестандартные 8443/9443/5000: там явных ожиданий нет.
    #
    # SMTP/POP3/IMAP разрешают tls — STARTTLS/STLS стандарт.
    # 80 разрешает tls — некоторые сервисы пускают HTTPS на 80.
    # 443 не в таблице: h2c и HTTP на 443 редки, а «ничего не
    # проверять на 443» — осознанный отказ от FP.
    port_service_allowed: Mapping[int, frozenset[str]] = field(
        default_factory=lambda: MappingProxyType({
            22:    frozenset({"ssh"}),
            23:    frozenset({"telnet"}),
            25:    frozenset({"smtp", "tls"}),     # STARTTLS
            53:    frozenset({"dns"}),
            80:    frozenset({"http", "tls"}),     # HTTPS на 80 бывает
            110:   frozenset({"pop3", "tls"}),     # STLS
            143:   frozenset({"imap", "tls"}),     # STARTTLS
            139:   frozenset({"netbios"}),
            445:   frozenset({"smb"}),
            1433:  frozenset({"mssql"}),
            1521:  frozenset({"oracle"}),
            3306:  frozenset({"mysql"}),
            3389:  frozenset({"rdp"}),
            5432:  frozenset({"postgres"}),
            5900:  frozenset({"vnc"}),
            6379:  frozenset({"redis"}),
            27017: frozenset({"mongodb"}),
        }),
    )
    # --- reverse asymmetry ---
    # Пропорция трафика в сессии: 5 МБ out при 50 КБ in — это
    # эксфильтрация или C2 beacon-behavior, даже если absolute
    # порог large_transfer (100 МБ) не пройден.
    #
    # min_total_bytes — абсолютный пол. Ниже — не смотрим (шум).
    # min_ratio — во сколько раз большая сторона должна превышать
    # меньшую. 10:1 — уже аномалия для нормального двустороннего
    # обмена. 25:1 — почти односторонний канал, high severity.
    reverse_asymmetry_min_total_bytes: int = 1024 * 1024  # 1 МБ
    reverse_asymmetry_min_ratio: float = 10.0
    reverse_asymmetry_high_ratio: float = 25.0

    # --- lateral movement ---
    lateral_movement_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({
            445,    # SMB
            135,    # MSRPC
            139,    # NetBIOS
            3389,   # RDP
            5985,   # WinRM HTTP
            5986,   # WinRM HTTPS
        }),
    )
    lateral_movement_min_flows_port_only: int = 5
    lateral_movement_ua_markers: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "WinRM", "PsExec", "Impacket", "wmiexec", "psexec",
            "evil-winrm", "ruby winrm", "Ruby WinRM",
        ),
    )
    lateral_movement_uri_markers: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "/wsman", "/cimv2", "/root/cimv2", "/wmi",
        ),
    )
    lateral_movement_admin_srcs: frozenset[str] = field(
        default_factory=frozenset,
    )

    # --- FTP brute force ---
    # Отдельно от HTTP-brute_force: FTP-сессия состоит из множества
    # пакетов (логин, MKD, LIST, data), поэтому avg_packets > 20
    # рубит HTTP-детектор. Ищем чистый признак: много flows
    # к одному (dst, 21) с уникальными src_ports.
    ftp_brute_force_min_flows: int = 20
    ftp_brute_force_min_unique_src_ports: int = 20


    # --- SSH brute force ---
    # SSH-клиент шлёт баннер один раз на соединение. Много баннеров
    # с одного src к одной (dst_ip, dst_port) — перебор паролей.
    # 20 — как ftp_brute_force, для консистентности.
    ssh_brute_force_min_flows: int = 20

    # --- SMTP spam ---
    # Массовая рассылка: с одного src много уникальных RCPT TO.
    # 50 — компромисс: меньше — легитимные рассылки на группу,
    # больше — теряем медленных спам-ботов.
    smtp_spam_min_recipients: int = 50

    # --- NXDOMAIN burst ---
    # v0.9.0: threshold — сколько NXDOMAIN в окне _window_sec.
    # Было: сколько за весь файл. Считаем максимум в скользящем
    # окне W секунд; на FIN-2015 93 → ожидаемо ~5-15.
    nxdomain_burst_threshold: int = 5
    nxdomain_burst_window_sec: int = 60
    # v0.9.0: минимум NXDOMAIN / всех DNS-запросов от src.
    # Ниже — шум (браузер с редкими опечатками в большой истории).
    # DGA/malware: >0.3 (мало успешных, много NXDOMAIN).
    nxdomain_burst_min_ratio: float = 0.2

    # --- typosquatting ---
    protected_brands: frozenset[str] = field(default_factory=lambda: _frozen(
        "microsoft", "google", "amazon", "apple", "facebook",
        "instagram", "whatsapp", "telegram", "paypal", "netflix",
        "gmail", "outlook", "office365", "windowsupdate", "dropbox",
        "binance", "metamask", "coinbase",
    ))

    legitimate_brand_domains: frozenset[str] = field(default_factory=lambda: _frozen(
        # Microsoft
        "microsoft.com", "live.com", "office.com", "outlook.com",
        "microsoftonline.com", "sharepoint.com", "microsoft365.com",
        "office365.com", "windowsupdate.com", "update.microsoft.com",
        "msn.com", "bing.com", "msedge.net", "ax-msedge.net",
        "smartscreen.microsoft.com",
        # Google
        "google.com", "gmail.com", "youtube.com", "googleapis.com",
        "doubleclick.net", "google-analytics.com", "googleadservices.com",
        "googlesyndication.com", "googletagmanager.com", "gstatic.com",
        "googlevideo.com", "googlecode.com", "googleusercontent.com",
        "withgoogle.com", "goo.gl",
        # Apple
        "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",
        # Amazon / AWS
        "amazon.com", "aws.amazon.com", "amazonaws.com",
        # Соцсети / сервисы
        "facebook.com", "fb.com", "instagram.com", "whatsapp.com",
        "twitter.com", "x.com", "t.co",
        "telegram.org", "paypal.com", "netflix.com",
        "dropbox.com", "binance.com", "metamask.io", "coinbase.com",
        # FP-триггеры (app.*)
        "loadimpact.com", "webinspector.com",
    ))
    typosquatting_levenshtein_threshold: int = 2

    # --- SNI mismatch ---
    sni_mismatch_min_flows: int = 1
    sni_mismatch_allowlist: frozenset[str] = field(default_factory=lambda: _frozen(
        "dns.google",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "doh.opendns.com",
        "dns.quad9.net",
        "nextdns.io",
        "ocsp.digicert.com",
        "ocsp.pki.goog",
        "crl.microsoft.com",
        "smartscreen.microsoft.com",
    ))

    # --- domain controller detection ---
    dc_service_ports: frozenset[int] = field(default_factory=lambda: frozenset({
        88,    # Kerberos
        389,   # LDAP
        445,   # SMB
        3268,  # LDAP Global Catalog
        636,   # LDAPS
    }))
    dc_min_service_flows: int = 20
    dc_min_unique_srcs: int = 1

    # --- brute force ---
    brute_force_min_flows: int = 20
    brute_force_max_avg_packets: int = 20
    brute_force_min_unique_src_ports: int = 10
    brute_force_uri_ratio_threshold: float = 0.3
    brute_force_min_rate_flows_per_sec: float = 0.01
    brute_force_excluded_ports: frozenset[int] = field(
        default_factory=frozenset, init=False,
    )
    brute_force_skip_tls_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({443, 8443}),
    )
    login_endpoint_hints: frozenset[str] = field(default_factory=lambda: _frozen(
        "/login", "/logon", "/signin", "/sign-in", "/auth",
        "/admin", "/administrator", "/wp-login", "/wp-admin",
        "/cpanel", "/webmail", "/phpmyadmin", "/pma",
        "/session", "/oauth", "/api/token",
    ))
    # URI, которые выглядят как «вход удался»: успешный ответ,
    # дашборд, страница после логина. Срабатывает только вместе с
    # brute_force на ту же пару (src, dst, port) — сам по себе этот
    # признак ничего не значит.
    #
    # Ограничение: в FlowStats нет HTTP-статуса, поэтому «success» —
    # это имя endpoint'а, а не подтверждённый 200. Отсюда confidence
    # ниже, чем у явного перехвата учётных данных.
    bruteforce_success_uri_hints: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "loginok",
            "login_ok",
            "loginsuccess",
            "login-success",
            "/success",
            "success.",
            "dashboard",
        ),
    )

    # --- vulnerable paths ---
    vulnerable_paths: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({
        "wp-content/plugins/post-content-shortcodes": "WP post-content-shortcodes",
        "wp-content/plugins/revslider": "Revslider RCE",
        "wp-content/plugins/contact-form-7": "CF7 arbitrary file upload",
        "wp-content/plugins/woocommerce": "WooCommerce",
        "wp-content/plugins/elementor": "Elementor",
        "wp-content/plugins/wp-file-manager": "WP File Manager RCE",
        "wp-content/plugins/duplicator": "Duplicator path traversal",
        "wp-login.php": "WP login",
        "wp-admin/": "WP admin",
        "xmlrpc.php": "WP xmlrpc pingback",
        "/.env": "dotenv exposure",
        "/.git/": "git repo leak",
        "/.aws/credentials": "AWS credentials",
        "/phpmyadmin/": "phpMyAdmin",
        "/phpinfo.php": "phpinfo leak",
        "/cgi-bin/": "CGI",
    }))

    suspicious_download_extensions: frozenset[str] = field(default_factory=lambda: _frozen(
        ".ps1", ".vbs", ".hta", ".jar", ".sh",
        ".exe", ".dll", ".scr", ".iso", ".img", ".lnk",
    ))
    web_scanner_min_distinct_paths: int = 10

    # --- entities ---
    entities_top_n: int = 50
    gateway_min_flows: int = 50
    gateway_min_unique_dsts: int = 10

    # --- flow report ---
    flow_report_top_n: int = 500

    # --- absence ---
    # Потолок строк в секциях «DNS без ответа» и «TCP без ответа».
    absence_top_n: int = 100

    # --- plugins ---
    # Пользовательские детекторы из ~/.paradox/plugins/*.py.
    # По умолчанию выключено: плагин — это код, который будет
    # исполнен в процессе анализа.
    plugins_enabled: bool = False
    plugins_dir: Path = Path.home() / ".paradox" / "plugins"

    # --- enrichment ---
    # Threat Intel. Не запускается в основном pipeline — только
    # по флагу --enrich. Требует сети.
    enrichment_cache_ttl_days: int = 7
    enrichment_cache_path: Path = Path("reports/.cache/enrichment.db")
    # Провайдеры вкл/выкл. Shodan InternetDB — без ключа, остальные
    # требуют ключ (см. env vars).
    # v0.9.0: расширено. Все безклчевые — включены. Требующие
    # ABUSECH_AUTH_KEY (urlhaus, malwarebazaar, threatfox) —
    # добавлены в REGISTRY, но не в дефолт: пользователь включит
    # после указания ключа.
    enrichment_enabled_providers: frozenset[str] = field(
        default_factory=lambda: _frozen(
            "shodan_internetdb",
            "abuseipdb",
            "virustotal",
            "greynoise",
            "alienvault_otx",
            "urlscan",
            # Требуют ABUSECH_AUTH_KEY. Без ключа BaseEnricher.enabled
            # возвращает False и провайдер не вызывается — но пусть
            # будет виден в списке «Настройки → Threat Intel».
            "urlhaus",
            "malwarebazaar",
            "threatfox",
        ),
    )
    # Сколько IOC обогащать за один прогон. Больше = дольше,
    # больше rate limit попаданий.
    enrichment_max_iocs: int = 100

    # --- debug ---
    # Логировать первую ошибку каждого экстрактора через
    # logging.exception. По умолчанию выключено: hot-loop
    # на 9.5M пакетов не должен платить за traceback при
    # единичных сбоях. Счётчик extractor_errors ведётся
    # всегда, независимо от флага.
    debug_log_extractor_errors: bool = False

    # --- output ---
    output_dir: Path = Path("reports")
    # v0.9.0: писать iocs.txt/csv/json + suricata.rules + queries.txt
    # в output_dir после каждого прогона. Файлы маленькие, полезны.
    ioc_export_enabled: bool = True

    # --- behavioral analysis (ML) ---
    # Статистические аномалии поверх flow-признаков (Isolation Forest).
    # По умолчанию выключено: статистика — подсказка для триажа, а не
    # вердикт, и без калибровки на эталонных захватах она шумит.
    #
    # contamination — какая доля сессий считается аномальной. Это
    # самосбывающийся прогноз (модель ВСЕГДА выдаст этот процент),
    # поэтому ниже confidence_min находка не создаётся вовсе.
    behavioral_enabled: bool = False
    # Калибровка 2026-11-12 на трёх эталонах: 0.05 давал 7 FP на чистом
    # FIRST-2015 (0 findings) и 23 на CyberCampTask; 0.02 снижает FP
    # вдвое (5 и 14), сохраняя сигнал. Чистый захват всё равно даёт
    # >=1 (тяжёлый хвост) — порогом это не лечится, нужен фильтр
    # мультикаста/линк-локал (см. behavioral_analyzer).
    behavioral_contamination: float = 0.02
    # Минимальный confidence, при котором сессия считается статистическим
    # выбросом и аннотирует совпавшие rule-находки (behavioral_corroborated).
    behavioral_confidence_min: float = 0.7
    # На захвате меньше этого числа flow Isolation Forest неустойчив:
    # случайные выбросы неотличимы от реальных, слой молчит.
    behavioral_min_flows: int = 50
    # Host-level: профиль хоста строится только при таком числе
    # внутренних хостов — на 2-3 хостах «аномалия профиля» бессмысленна.
    behavioral_min_hosts: int = 10
    # Верхний предохранитель: не заваливать отчёт статистическим шумом.
    behavioral_max_findings: int = 50
    # Детерминизм. A-Detector не задаёт random_state — результат у него
    # меняется от прогона к прогону; для SOC-инструмента это неприемлемо.
    behavioral_seed: int = 42

    # --- role deviation (правило contradictions role_deviation) ---
    # Сканером считается хост, инициировавший SYN к >= min_targets пар
    # (dst_ip, dst_port) на >= min_ports разных портах. Критерий «разные
    # порты» отличает сканер от браузера (сотни IP, но 1-2 порта).
    role_scanner_min_targets: int = 20
    role_scanner_min_ports: int = 5
    # Минимум байт, отданных хостом на src_port 80/443/445, чтобы
    # считать его «отвечающим как сервер». Отсекает голые handshake.
    role_server_min_bytes: int = 256

    def __post_init__(self) -> None:
        # dga_allowlist = extra + tunnel-домены + ip-check сервисы.
        merged_dga = set(self._dga_allowlist_extra)
        merged_dga |= self.cloud_tunnel_domains
        merged_dga |= self.ip_check_services
        object.__setattr__(self, "dga_allowlist", frozenset(merged_dga))

        # brute_force_excluded_ports = alias на dc_service_ports.
        object.__setattr__(
            self, "brute_force_excluded_ports",
            frozenset(self.dc_service_ports),
        )

        self._validate()

    def _validate(self) -> None:
        errors = [
            rule.message
            for rule in _VALIDATION_RULES
            if not rule.valid(getattr(self, rule.field))
        ]
        if errors:
            raise ValueError(
                "Invalid Config:\n" + "\n".join(f"  - {e}" for e in errors)
            )
