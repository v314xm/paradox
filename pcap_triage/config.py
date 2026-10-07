from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # --- DGA ---
    dga_entropy_threshold: float = 3.5
    dga_min_label_length: int = 12
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
    })

    # --- suspicious ports ---
    suspicious_ports: set[int] = field(default_factory=lambda: {
        21, 22, 23, 4444, 1337, 31337, 8080, 8443, 12132,
    })

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
        "dropbox.com", "binance.com", "metamask.io", "coinbase.com",
    })

    typosquatting_levenshtein_threshold: int = 2
    # --- flow report ---
    flow_report_top_n: int = 100

    # --- output ---
    output_dir: Path = Path("reports")