"""
MITRE ATT&CK mapping для детекторов Paradox.

Ключи совпадают с Finding.type.
"""

MITRE_MAP: dict[str, tuple[str, ...]] = {
    # Reconnaissance
    "port_scan": ("T1046",),
    "web_scanner": ("T1595.002",),
    "vulnerable_path": ("T1190",),

    # Initial Access
    "brute_force": ("T1110.001",),
    "ftp_brute_force": ("T1110.001",),
    "ssh_brute_force": ("T1110.001", "T1021.004"),
    "script_download": ("T1189",),
    "typosquatting": ("T1583.001",),
    "smtp_spam": ("T1583.002",),

    # Execution
    # command_injection: RCE через HTTP (URI / POST body) —
    # эксплуатирует публично доступный сервис (T1190) и вызывает
    # интерпретатор (T1059). Обе техники уместны.
    "command_injection": ("T1190", "T1059"),
    # yara_match: YARA-сигнатура malware в скачанном payload —
    # обнаружение и попытка запуска (T1204).
    "yara_match": ("T1204",),

    # Command and Control
    "dga_domain": ("T1568.002",),
    "cloud_tunnel": ("T1572",),
    "cloud_tunnel_domain": ("T1572",),   # старое имя — оставлено для совместимости
    "large_transfer": ("T1041",),
    "ip_check_service": ("T1016",),
    "sni_without_dns": ("T1071.001",),

    # C2-beaconing / exfil / fingerprinting
    "beaconing": ("T1071.001",),         # Web Protocols — heartbeat через HTTP(S)
    "dns_tunneling": ("T1071.004",),     # DNS
    "ja3_malware": ("T1071.001",),       # известный malware-JA3

    # Domain fronting / SNI-mismatch
    "sni_mismatch": ("T1071.001",),

    # Lateral Movement
    "lateral_movement": (
        "T1021.001",
        "T1021.002",
        "T1021.006",
    ),

    # Discovery
    "nxdomain_burst": ("T1568.002",),
    "suspicious_port": ("T1571",),
}


def get_techniques(finding_type: str) -> tuple[str, ...]:
    return MITRE_MAP.get(finding_type, ())
