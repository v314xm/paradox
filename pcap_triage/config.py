from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # --- DGA ---
    dga_entropy_threshold: float = 3.5
    dga_min_label_length: int = 12
    # DGA по энтропии не отличает легитимный Azure VM
    # (onedscolprdeus06.eastus.cloudapp.azure.com) от C2 на Azure
    # (evil-abc123.cloudapp.azure.com). Allowlist убирает ложные
    # срабатывания DGA, но НЕ означает доверие: такие домены
    # проверяются другими детекторами (suspicious_port, beaconing)
    # и threat intel.
    dga_allowlist: set[str] = field(default_factory=lambda: {
         "amazonaws.com",
        "cloudfront.net",
        "azureedge.net",
        "akamaiedge.net",
        "googleusercontent.com",
        "windowsupdate.com",
        "google.com",           # ← добавили
        # cloud tunnels — легитимные поддомены, но энтропия высокая
        "trycloudflare.com",
        "ngrok.io",
        "ngrok-free.app",
        "serveo.net",
        "localtunnel.me",
        "lhr.life",
        "pinggy.io",
        # ip check services
        "ip-api.com",
        "ipinfo.io",
        "ifconfig.me",
        "icanhazip.com",
        "api.ipify.org",
        "ipify.org",
        "myexternalip.com",
        "checkip.amazonaws.com",
        "cloudapp.azure.com",
        "cloudapp.azure.com",
    })

    # --- suspicious ports ---
    suspicious_ports: set[int] = field(default_factory=lambda: {
        21,  # FTP
        22,  # SSH (наружу)
        23,  # Telnet
        4444,  # Metasploit default
        1337,  # leet
        31337,  # Back Orifice / leet
        8080,  # alt-http
        8443,  # alt-https
        12132,  # STRRAT из примеров
    })
    # Приватные сети — адреса, для которых suspicious_port НЕ срабатывает.
    # Смысл сигнала — «внутренний клиент стучится наружу на нестандартный порт».
    # Внутренний → внутренний — это нормальная работа, не сигнал.
    private_networks: tuple[str, ...] = (
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "127.",
        "169.254.",  # link-local
        "224.", "239.",  # multicast
        "255.255.255.255",
    )
    # --- NXDOMAIN burst ---
    nxdomain_burst_threshold: int = 5

    # --- cloud tunnel domains ---
    cloud_tunnel_domains: set[str] = field(default_factory=lambda: {
        "trycloudflare.com",
        "ngrok.io",
        "ngrok-free.app",
        "serveo.net",
        "localtunnel.me",
        "lhr.life",
        "pinggy.io",
    })

    # --- ip check services ---
    ip_check_services: set[str] = field(default_factory=lambda: {
        "ip-api.com",
        "ipinfo.io",
        "ifconfig.me",
        "icanhazip.com",
        "api.ipify.org",
        "ipify.org",
        "myexternalip.com",
        "checkip.amazonaws.com",
    })
    # --- typosquatting ---
    protected_brands: set[str] = field(default_factory=lambda: {
        "microsoft",
        "google",
        "amazon",
        "apple",
        "facebook",
        "instagram",
        "whatsapp",
        "telegram",
        "paypal",
        "netflix",
        "gmail",
        "outlook",
        "office365",
        "windowsupdate",
        "dropbox",
        "binance",
        "metamask",
        "coinbase",
    })

    # Официальные домены брендов, которые НЕ должны флагаться.
    # Совпадение по точному имени или по суффиксу.
    legitimate_brand_domains: set[str] = field(default_factory=lambda: {
        "microsoft.com", "live.com", "office.com", "outlook.com",
        "microsoftonline.com", "sharepoint.com", "microsoft365.com",
        "google.com", "gmail.com", "youtube.com", "googleapis.com",
        "amazon.com", "aws.amazon.com", "amazonaws.com",
        "apple.com", "icloud.com",
        "facebook.com", "fb.com", "instagram.com", "whatsapp.com",
        "telegram.org", "paypal.com", "netflix.com",
        "office365.com", "windowsupdate.com", "update.microsoft.com",
        "dropbox.com", "binance.com", "metamask.io", "coinbase.com", "msedge.net", "ax-msedge.net",
    })

    typosquatting_levenshtein_threshold: int = 2

    # --- SNI mismatch ---
    # Минимум flows с одинаковым SNI, чтобы сработать. 1 — срабатывать
    # на первое же соединение. Можно поднять, если шумит.
    sni_mismatch_min_flows: int = 1

    # SNI, которые не проверяем на совпадение с DNS.
    # DoH-сервисы — их SNI по определению не в DNS (это их работа).
    # Легитимные трекеры/телеметрия, чьи DNS-запросы могут быть
    # вне окна захвата.
    sni_mismatch_allowlist: set[str] = field(default_factory=lambda: {
        # DNS over HTTPS
        "dns.google",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "doh.opendns.com",
        "dns.quad9.net",
        "nextdns.io",
        # Certificate / OCSP (часто идут до/после основного запроса)
        "ocsp.digicert.com",
        "ocsp.pki.goog",
        "crl.microsoft.com",
        "smartscreen.microsoft.com",
    })
    # --- brute force ---
    # Много коротких flows с одного src_ip к одной паре dst_ip:dst_port.
    # Не срабатывает на: длинную сессию (много пакетов на flow),
    # port scan (много портов, но по 1-3 пакета и разным dst_port).
    brute_force_min_flows: int = 20
    brute_force_max_avg_packets: int = 20
    brute_force_min_unique_src_ports: int = 10

    # --- vulnerable paths ---
    # Подстроки в http_uri. Если URI содержит одну из них — finding.
    # Сигнал: обращение к известной уязвимой точке (сканер, эксплуатация,
    # либо легитимная работа с устаревшим плагином — решать аналитику).
    # ВАЖНО: расширения скриптов здесь НЕ дублируем — они в
    # suspicious_download_extensions ниже.
    vulnerable_paths: dict[str, str] = field(default_factory=lambda: {
        # WordPress-плагины с известными CVE
        "wp-content/plugins/post-content-shortcodes": "WP post-content-shortcodes",
        "wp-content/plugins/revslider": "Revslider RCE",
        "wp-content/plugins/contact-form-7": "CF7 arbitrary file upload",
        "wp-content/plugins/woocommerce": "WooCommerce",
        "wp-content/plugins/elementor": "Elementor",
        "wp-content/plugins/wp-file-manager": "WP File Manager RCE",
        "wp-content/plugins/duplicator": "Duplicator path traversal",
        # Управление WordPress
        "wp-login.php": "WP login",
        "wp-admin/": "WP admin",
        "xmlrpc.php": "WP xmlrpc pingback",
        # Утечки
        "/.env": "dotenv exposure",
        "/.git/": "git repo leak",
        "/.aws/credentials": "AWS credentials",
        "/phpmyadmin/": "phpMyAdmin",
        "/phpinfo.php": "phpinfo leak",
        "/cgi-bin/": "CGI",
    })

    # --- suspicious download extensions ---
    # Расширения, скачивание которых — отдельный сигнал script_download.
    # Проверяются в VulnerablePathDetector, если URI не совпал
    # ни с одним vulnerable_path.
    suspicious_download_extensions: set[str] = field(default_factory=lambda: {
        ".ps1", ".vbs", ".hta", ".js", ".jar", ".sh",
        ".exe", ".dll", ".scr", ".iso", ".img", ".lnk",
    })


    # --- entities ---
    entities_top_n: int = 50
    gateway_min_flows: int = 50
    gateway_min_unique_dsts: int = 10

    # --- flow report ---
    flow_report_top_n: int = 500

    # --- output ---
    output_dir: Path = Path("reports")