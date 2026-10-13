"""
MITRE ATT&CK mapping для детекторов pcap-triage.

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
    "script_download": ("T1189",),
    "typosquatting": ("T1583.001",),

    # Command and Control
    "dga_domain": ("T1568.002",),
    "cloud_tunnel_domain": ("T1572",),
    "large_transfer": ("T1041",),
    "ip_check_service": ("T1016",),
    "sni_without_dns": ("T1071.001",),

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