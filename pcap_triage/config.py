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
    ))
    dga_allowlist: frozenset[str] = field(default_factory=frozenset, init=False)

    # --- suspicious ports ---
    suspicious_ports: frozenset[int] = field(default_factory=lambda: frozenset({
        21,     # FTP
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
    # Если один src_ip стучится к >= N разным dst_ip на один dst_port —
    # это сканирование, а не «много подозрительных соединений».
    # Каждый dst_ip в отдельности выглядит как suspicious_port finding,
    # но 71 finding на один src — шум, скрывающий суть: атака одним хостом.
    port_scan_min_distinct_dsts: int = 10
    # Минимальный порог flow_count per (src, dst) — если у пары много
    # flow'ов, это уже не скан, а что-то осмысленное (сессия, retry).
    port_scan_max_flows_per_dst: int = 3


    # --- NXDOMAIN burst ---
    nxdomain_burst_threshold: int = 5

    # --- typosquatting ---
    protected_brands: frozenset[str] = field(default_factory=lambda: _frozen(
        "microsoft", "google", "amazon", "apple", "facebook",
        "instagram", "whatsapp", "telegram", "paypal", "netflix",
        "gmail", "outlook", "office365", "windowsupdate", "dropbox",
        "binance", "metamask", "coinbase"

    # Google — легитимные домены и CDN
    "doubleclick.net", "google-analytics.com", "googleadservices.com",
    "googlesyndication.com", "googletagmanager.com", "googleapis.com",
    "gstatic.com", "googlevideo.com", "youtube.com", "googlecode.com",
    "googleusercontent.com", "withgoogle.com",

    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",

    # Microsoft
    "microsoft.com", "microsoftonline.com", "live.com", "office.com",
    "msn.com", "bing.com", "windowsupdate.com", "msedge.net",
    "smartscreen.microsoft.com",

    # Analytics / monitoring (FP-триггеры на app.*)
    "loadimpact.com", "webinspector.com",

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
    # Порог отсеивания по уникальным URI: при подборе пароля URI
    # один и тот же (/login.php), ratio близко к 0. При нормальной
    # работе URI разные, ratio ближе к 1.
    brute_force_uri_ratio_threshold: float = 0.3
    # Минимальная скорость попыток (flow/s). Настоящий подбор
    # пароля либо быстрый (десятки попыток в секунду), либо
    # с rate limiting на сервере (одна попытка в 30 секунд ≈ 0.03).
    # Если реже — это поллинг (Firefox Safe Browsing переоткрывает
    # соединение раз в 15 минут), а не подбор.
    brute_force_min_rate_flows_per_sec: float = 0.01
    # Порты, которые brute_force НЕ проверяет. В __post_init__
    # устанавливается как alias на dc_service_ports.
    brute_force_excluded_ports: frozenset[int] = field(
        default_factory=frozenset, init=False,
    )
    # Порты, на которых массовые TCP-соединения — норма (браузер к CDN),
    # а не подбор пароля. Подбор через HTTPS идёт как POST внутри
    # существующего соединения.
    brute_force_skip_tls_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({443, 8443}),
    )

    # Подстроки, которые должны быть в HTTP URI для подбора пароля.
    # Настоящий brute force всегда идёт на login endpoint. Если у flow'ов
    # только /image.jpg и /style.css — это браузер, а не подбор.
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

    # .js исключён намеренно: JavaScript есть на каждом сайте,
    # это даёт тысячи FP. Malware может использовать .js, но это
    # ловится через обфускацию (ObfuscationDetector — TODO), а не
    # через расширение.
    suspicious_download_extensions: frozenset[str] = field(default_factory=lambda: _frozen(
        ".ps1", ".vbs", ".hta", ".jar", ".sh",
        ".exe", ".dll", ".scr", ".iso", ".img", ".lnk",
    ))
    # Порог для определения web-сканера: если один src обратился
    # к >= N разным уязвимым путям/скриптам к одной цели — это
    # сканер, а не набор отдельных атак.
    web_scanner_min_distinct_paths: int = 10
    # --- entities ---
    entities_top_n: int = 50
    gateway_min_flows: int = 50
    gateway_min_unique_dsts: int = 10

    # --- flow report ---
    flow_report_top_n: int = 500

    # --- output ---
    output_dir: Path = Path("reports")

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

        if self.dga_entropy_threshold <= 0:
            errors.append("dga_entropy_threshold must be > 0")
        if self.dga_min_label_length <= 0:
            errors.append("dga_min_label_length must be > 0")
        if self.nxdomain_burst_threshold <= 0:
            errors.append("nxdomain_burst_threshold must be > 0")
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