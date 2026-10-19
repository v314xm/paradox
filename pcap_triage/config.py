from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


def _frozen(*items: str) -> frozenset[str]:
    return frozenset(items)


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

    # --- command injection ---
    # Паттерны RCE в HTTP URI/body. Два уровня confidence.
    #
    # high — почти наверняка RCE (языковые конструкции)
    command_injection_patterns_high: frozenset[str] = field(
        default_factory=lambda: _frozen(
            # Lua (OpenResty, Nginx-модули)
            "io.popen", "os.execute",
            # PHP
            "system(", "exec(", "shell_exec(", "passthru(",
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
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _validate(self) -> None:
        errors: list[str] = []

        if self.file_carve_min_size <= 0:
            errors.append("file_carve_min_size must be > 0")
        if self.file_carve_max_size <= 0:
            errors.append("file_carve_max_size must be > 0")
        if self.command_injection_min_patterns <= 0:
            errors.append("command_injection_min_patterns must be > 0")
        if self.command_injection_aggregate_min <= 0:
            errors.append("command_injection_aggregate_min must be > 0")
        if self.tcp_reassembly_max_bytes_per_flow <= 0:
            errors.append("tcp_reassembly_max_bytes_per_flow must be > 0")
        if self.tcp_reassembly_max_total_bytes <= 0:
            errors.append("tcp_reassembly_max_total_bytes must be > 0")
        if self.enrichment_cache_ttl_days <= 0:
            errors.append("enrichment_cache_ttl_days must be > 0")
        if self.enrichment_max_iocs <= 0:
            errors.append("enrichment_max_iocs must be > 0")
        if self.dns_tunneling_min_qname_length <= 0:
            errors.append("dns_tunneling_min_qname_length must be > 0")
        if self.dns_tunneling_min_long_qnames <= 0:
            errors.append("dns_tunneling_min_long_qnames must be > 0")
        if self.dns_tunneling_min_queries <= 0:
            errors.append("dns_tunneling_min_queries must be > 0")
        if self.beaconing_min_connections <= 0:
            errors.append("beaconing_min_connections must be > 0")
        if self.beaconing_min_duration_sec <= 0:
            errors.append("beaconing_min_duration_sec must be > 0")
        if not (0.0 < self.beaconing_max_jitter_ratio <= 1.0):
            errors.append(
                "beaconing_max_jitter_ratio must be in (0, 1]"
            )
        if self.beaconing_max_avg_bytes <= 0:
            errors.append("beaconing_max_avg_bytes must be > 0")
        if self.beaconing_max_flows_per_minute <= 0:
            errors.append("beaconing_max_flows_per_minute must be > 0")
        if self.beaconing_payload_stddev_ratio_max < 0:
            errors.append(
                "beaconing_payload_stddev_ratio_max must be >= 0"
            )
        if not self.beaconing_mail_polling_ports:
            errors.append("beaconing_mail_polling_ports must not be empty")
        if any(
            p <= 0 or p > 65535
            for p in self.beaconing_mail_polling_ports
        ):
            errors.append(
                "beaconing_mail_polling_ports must be in range 1..65535"
            )
        if self.ftp_brute_force_min_flows <= 0:
            errors.append("ftp_brute_force_min_flows must be > 0")
        if self.ssh_brute_force_min_flows <= 0:
            errors.append("ssh_brute_force_min_flows must be > 0")
        if self.smtp_spam_min_recipients <= 0:
            errors.append("smtp_spam_min_recipients must be > 0")
        if self.ftp_brute_force_min_unique_src_ports <= 0:
            errors.append(
                "ftp_brute_force_min_unique_src_ports must be > 0"
            )

        if self.large_transfer_min_bytes <= 0:
            errors.append("large_transfer_min_bytes must be > 0")
        if self.lateral_movement_min_flows_port_only <= 0:
            errors.append("lateral_movement_min_flows_port_only must be > 0")
        if not self.lateral_movement_ports:
            errors.append("lateral_movement_ports must not be empty")
        if self.dga_entropy_threshold <= 0:
            errors.append("dga_entropy_threshold must be > 0")
        if self.dga_min_label_length <= 0:
            errors.append("dga_min_label_length must be > 0")
        if self.nxdomain_burst_threshold <= 0:
            errors.append("nxdomain_burst_threshold must be > 0")
        if self.nxdomain_burst_window_sec <= 0:
            errors.append("nxdomain_burst_window_sec must be > 0")
        if not (0.0 < self.nxdomain_burst_min_ratio <= 1.0):
            errors.append(
                "nxdomain_burst_min_ratio must be in (0, 1]"
            )
        if self.typosquatting_levenshtein_threshold < 0:
            errors.append("typosquatting_levenshtein_threshold must be >= 0")
        if self.sni_mismatch_min_flows <= 0:
            errors.append("sni_mismatch_min_flows must be > 0")
        if self.brute_force_min_flows <= 0:
            errors.append("brute_force_min_flows must be > 0")
        if self.brute_force_max_avg_packets <= 0:
            errors.append("brute_force_max_avg_packets must be > 0")
        if self.brute_force_min_unique_src_ports <= 0:
            errors.append("brute_force_min_unique_src_ports must be > 0")
        if not (0.0 < self.brute_force_uri_ratio_threshold <= 1.0):
            errors.append(
                "brute_force_uri_ratio_threshold must be in (0, 1]"
            )
        if self.brute_force_min_rate_flows_per_sec <= 0:
            errors.append(
                "brute_force_min_rate_flows_per_sec must be > 0"
            )
        if self.dc_min_service_flows <= 0:
            errors.append("dc_min_service_flows must be > 0")
        if self.dc_min_unique_srcs <= 0:
            errors.append("dc_min_unique_srcs must be > 0")
        if self.entities_top_n <= 0:
            errors.append("entities_top_n must be > 0")
        if self.gateway_min_flows <= 0:
            errors.append("gateway_min_flows must be > 0")
        if self.gateway_min_unique_dsts <= 0:
            errors.append("gateway_min_unique_dsts must be > 0")
        if self.flow_report_top_n <= 0:
            errors.append("flow_report_top_n must be > 0")
        if self.web_scanner_min_distinct_paths <= 0:
            errors.append("web_scanner_min_distinct_paths must be > 0")
        if self.port_scan_min_distinct_dsts <= 0:
            errors.append("port_scan_min_distinct_dsts must be > 0")
        if self.port_scan_max_flows_per_dst <= 0:
            errors.append("port_scan_max_flows_per_dst must be > 0")
        if not self.port_scan_excluded_ports:
            errors.append("port_scan_excluded_ports must not be empty")
        if any(p <= 0 or p > 65535 for p in self.port_scan_excluded_ports):
            errors.append(
                "port_scan_excluded_ports must be in range 1..65535"
            )
        if not self.suspicious_ports:
            errors.append("suspicious_ports must not be empty")
        if not self.dc_service_ports:
            errors.append("dc_service_ports must not be empty")
        if any(p <= 0 or p > 65535 for p in self.suspicious_ports):
            errors.append("suspicious_ports must be in range 1..65535")
        if any(p <= 0 or p > 65535 for p in self.dc_service_ports):
            errors.append("dc_service_ports must be in range 1..65535")

        if errors:
            raise ValueError(
                "Invalid Config:\n" + "\n".join(f"  - {e}" for e in errors)
            )