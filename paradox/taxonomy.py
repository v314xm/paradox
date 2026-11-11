"""
Единый источник правды о типах findings.

Здесь и только здесь задаётся:
  - severity по умолчанию;
  - кто атакующий, а кто жертва (полярность src/dst);
  - MITRE ATT&CK;
  - фаза kill-chain и порядок в TL;DR.

Раньше эти таблицы дублировались в models, facts, entities, timeline,
attack_graph, mitre_map и трёх reporter'ах. Копии уже расходились:
исходящая эксфильтрация (`http_binary_upload`) помечалась как атака
внутреннего хоста на внешний, а `ja3s_malware` выпадал из фаз графа.

Правило: новый тип finding — одна строка в каждой таблице ниже.
Тест `tests/test_taxonomy.py` проверяет, что типы из детекторов
описаны везде, где нужно.
"""
from __future__ import annotations

# ---------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------

SEVERITY_BY_TYPE: dict[str, str] = {
    "command_injection": "high",
    "brute_force": "high",
    "successful_bruteforce": "high",
    "ftp_brute_force": "high",
    "ssh_brute_force": "high",
    "lateral_movement": "high",
    "ja3_malware": "high",
    "ja3s_malware": "high",
    "script_download": "high",
    "yara_match": "high",
    "http_binary_upload": "high",
    "php_download": "high",
    "webshell_upload": "critical",
    "webshell_signature": "critical",

    "port_scan": "medium",
    "web_scanner": "medium",
    "vulnerable_path": "medium",
    "beaconing": "medium",
    "dns_tunneling": "medium",
    "suspicious_port": "medium",
    "cloud_tunnel": "medium",
    "cloud_tunnel_domain": "medium",
    "sni_mismatch": "medium",
    "rare_external_ip": "medium",
    "encoded_payload": "medium",
    "long_connection": "medium",
    "dga_domain": "medium",
    "smtp_spam": "medium",
    "sni_without_dns": "medium",
    "large_transfer": "medium",
    "carved_file": "medium",

    "nxdomain_burst": "low",
    "typosquatting": "low",
    "ip_check_service": "low",
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1,
}

# Порядок для сортировки «critical сначала».
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


# ---------------------------------------------------------------------
# Полярность: роль src_ip в finding
# ---------------------------------------------------------------------
# "attacker" — src атакует dst, dst жертва.
# "victim"   — src жертва (инициатор/C2-клиент), dst — C2/exfil-получатель.
# None       — роль из finding не выводится (large_transfer, carved_file).

SRC_ROLE_BY_TYPE: dict[str, str] = {
    # src атакует dst
    "brute_force": "attacker",
    "successful_bruteforce": "attacker",
    "ftp_brute_force": "attacker",
    "ssh_brute_force": "attacker",
    "vulnerable_path": "attacker",
    "command_injection": "attacker",
    "port_scan": "attacker",
    "web_scanner": "attacker",
    "lateral_movement": "attacker",
    # Ответ сервера с malware: src — сервер-источник payload.
    "yara_match": "attacker",
    "php_download": "attacker",
    "webshell_upload": "attacker",
    "webshell_signature": "attacker",

    # src — жертва/инициатор, dst — C2 или получатель эксфильтрации
    "beaconing": "victim",
    "dns_tunneling": "victim",
    "script_download": "victim",
    "nxdomain_burst": "victim",
    "ja3_malware": "victim",
    "ja3s_malware": "victim",
    "sni_without_dns": "victim",
    "sni_mismatch": "victim",
    "rare_external_ip": "victim",
    "encoded_payload": "victim",
    "long_connection": "victim",
    "dga_domain": "victim",
    "cloud_tunnel": "victim",
    "cloud_tunnel_domain": "victim",
    "ip_check_service": "victim",
    "typosquatting": "victim",
    "suspicious_port": "victim",
    "smtp_spam": "victim",
    # Исходящая загрузка бинарного тела на внешний хост: src — жертва.
    "http_binary_upload": "victim",
}

# Роли, которые дополнительно помечаются как разведка.
SCANNER_TYPES: frozenset[str] = frozenset({"port_scan", "web_scanner"})


# ---------------------------------------------------------------------
# Роли сущностей → точки входа и воздействия (attack_graph)
# ---------------------------------------------------------------------
# Роли ставит aggregators/entities.py; attack_graph читает их, а не
# выводит entry/impact заново из собственных списков фаз.

ENTRY_ROLES: frozenset[str] = frozenset({"victim_candidate"})
IMPACT_ROLES: frozenset[str] = frozenset({
    "c2_candidate", "attacker_candidate",
})

# Фазы — запасной путь, когда ролей нет (entities не переданы).
ENTRY_PHASES: frozenset[str] = frozenset({"initial_access", "execution"})
IMPACT_PHASES: frozenset[str] = frozenset({"c2", "exfiltration", "impact"})

# Правило contradictions, которым помечается pivot.
PIVOT_RULE = "victim_makes_attack"


def pivot_subjects(contradictions: list | None) -> set[str]:
    """IP, для которых сработало правило victim_makes_attack.

    Duck-typing: taxonomy не импортирует contradictions (цикл импортов).
    Контракт: у объекта есть атрибуты .rule (str) и .subject (str).
    """
    out: set[str] = set()
    for c in contradictions or ():
        if getattr(c, "rule", None) != PIVOT_RULE:
            continue
        subject = getattr(c, "subject", None)
        if subject:
            out.add(subject)
    return out


# ---------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------

MITRE_BY_TYPE: dict[str, tuple[str, ...]] = {
    # Reconnaissance
    "port_scan": ("T1046",),
    "web_scanner": ("T1595.002",),
    "vulnerable_path": ("T1190",),

    # Initial Access
    "brute_force": ("T1110.001",),
    "successful_bruteforce": ("T1110.001", "T1078"),
    "ftp_brute_force": ("T1110.001",),
    "ssh_brute_force": ("T1110.001", "T1021.004"),
    "script_download": ("T1189",),
    "typosquatting": ("T1583.001",),
    "smtp_spam": ("T1583.002",),

    # Execution
    "command_injection": ("T1190", "T1059"),
    "yara_match": ("T1204",),

    # Command and Control
    "dga_domain": ("T1568.002",),
    "cloud_tunnel": ("T1572",),
    "cloud_tunnel_domain": ("T1572",),
    "large_transfer": ("T1041",),
    "ip_check_service": ("T1016",),
    "sni_without_dns": ("T1071.001",),
    "beaconing": ("T1071.001",),
    "http_binary_upload": ("T1071.001", "T1041"),
    "php_download": ("T1105",),
    "webshell_upload": ("T1505.003",),
    "webshell_signature": ("T1505.003",),
    "dns_tunneling": ("T1071.004",),
    "ja3_malware": ("T1071.001",),
    "ja3s_malware": ("T1071.001",),
    "sni_mismatch": ("T1071.001",),
    "rare_external_ip": ("T1071.001",),
    "encoded_payload": ("T1132.001", "T1041"),
    "long_connection": ("T1071",),

    # Lateral Movement
    "lateral_movement": ("T1021.001", "T1021.002", "T1021.006"),

    # Discovery
    "nxdomain_burst": ("T1568.002",),
    "suspicious_port": ("T1571",),
}

MITRE_NAMES: dict[str, str] = {
    "T1046": "Network Service Discovery",
    "T1595.002": "Vulnerability Scanning",
    "T1190": "Exploit Public-Facing App",
    "T1110.001": "Password Guessing",
    "T1078": "Valid Accounts",
    "T1021.004": "Remote Services: SSH",
    "T1189": "Drive-by Compromise",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1583.002": "Acquire Infrastructure: Servers",
    "T1059": "Command & Scripting Interpreter",
    "T1204": "User Execution",
    "T1568.002": "Domain Generation Algorithms",
    "T1572": "Protocol Tunneling",
    "T1041": "Exfiltration Over C2 Channel",
    "T1016": "System Network Configuration Discovery",
    "T1071.001": "Web Protocols",
    "T1071": "Application Layer Protocol",
    "T1132.001": "Data Encoding: Standard Encoding",
    "T1105": "Ingress Tool Transfer",
    "T1505.003": "Server Software Component: Web Shell",
    "T1071.004": "DNS",
    "T1021.001": "Remote Services: RDP",
    "T1021.002": "Remote Services: SMB",
    "T1021.006": "Remote Services: WinRM",
    "T1571": "Non-Standard Port",
}


def get_techniques(finding_type: str) -> tuple[str, ...]:
    return MITRE_BY_TYPE.get(finding_type, ())


def mitre_label(finding_type: str) -> str:
    """Строка для отчёта: `T1110.001 (Password Guessing)`."""
    techniques = get_techniques(finding_type)
    if not techniques:
        return "—"
    return ", ".join(
        f"{t} ({MITRE_NAMES[t]})" if t in MITRE_NAMES else t
        for t in techniques
    )


# ---------------------------------------------------------------------
# Kill-chain
# ---------------------------------------------------------------------

PHASE_BY_TYPE: dict[str, str] = {
    # Reconnaissance
    "port_scan": "recon",
    "web_scanner": "recon",

    # Initial Access
    "vulnerable_path": "initial_access",
    "brute_force": "initial_access",
    "successful_bruteforce": "initial_access",
    "ftp_brute_force": "initial_access",
    "ssh_brute_force": "initial_access",
    "typosquatting": "initial_access",

    # Execution
    "command_injection": "execution",
    "script_download": "execution",
    "php_download": "execution",
    "webshell_upload": "execution",
    "webshell_signature": "execution",
    "carved_file": "execution",
    "yara_match": "execution",

    # Command and Control
    "beaconing": "c2",
    "dns_tunneling": "c2",
    "dga_domain": "c2",
    "cloud_tunnel": "c2",
    "cloud_tunnel_domain": "c2",
    "ja3_malware": "c2",
    "ja3s_malware": "c2",
    "http_binary_upload": "exfiltration",
    "ip_check_service": "c2",
    "sni_without_dns": "c2",
    "sni_mismatch": "c2",
    "rare_external_ip": "c2",
    "encoded_payload": "exfiltration",
    "long_connection": "c2",
    "suspicious_port": "c2",
    "nxdomain_burst": "c2",

    # Lateral Movement
    "lateral_movement": "lateral_movement",

    # Exfiltration
    "large_transfer": "exfiltration",

    # Impact
    "smtp_spam": "impact",
}

PHASE_ORDER: dict[str, int] = {
    "recon": 10,
    "initial_access": 20,
    "execution": 30,
    "persistence": 40,
    "lateral_movement": 50,
    "c2": 60,
    "exfiltration": 70,
    "impact": 80,
    "other": 999,
}


def phase_for(finding_type: str) -> str:
    return PHASE_BY_TYPE.get(finding_type, "other")


# Порядок в TL;DR: гранулярнее фаз, но для знакомых типов сохранён
# прежний смысл (pivot первым, разведка → эксплуатация → C2 → эксфильтрация).
CHAIN_ORDER: dict[str, int] = {
    "pivot": 5,
    "web_scanner": 10,
    "port_scan": 20,
    "vulnerable_path": 30,
    "command_injection": 40,
    "brute_force": 50,
    "successful_bruteforce": 51,
    "ftp_brute_force": 55,
    "ssh_brute_force": 57,
    "script_download": 60,
    "carved_file": 65,
    "php_download": 66,
    "yara_match": 67,
    "webshell_upload": 68,
    "webshell_signature": 69,
    "suspicious_port": 70,
    "ja3_malware": 75,
    "ja3s_malware": 76,
    "beaconing": 80,
    "http_binary_upload": 81,
    "dns_tunneling": 82,
    "long_connection": 83,
    "dga_domain": 84,
    "encoded_payload": 85,
    "nxdomain_burst": 86,
    "typosquatting": 88,
    "cloud_tunnel": 90,
    "cloud_tunnel_domain": 90,
    "rare_external_ip": 91,
    "sni_without_dns": 92,
    "sni_mismatch": 93,
    "ip_check_service": 94,
    "lateral_movement": 100,
    "large_transfer": 110,
    "smtp_spam": 120,
}
CHAIN_UNKNOWN = 999


def chain_order_for(finding_type: str) -> int:
    return CHAIN_ORDER.get(finding_type, CHAIN_UNKNOWN)
