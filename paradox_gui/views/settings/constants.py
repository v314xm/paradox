"""Постоянные списки секций, детекторов и правил вкладки «Настройки»."""
from __future__ import annotations

_SECTIONS = (
    ("general",       "Общие"),
    ("thresholds",    "Пороги"),
    ("detectors",     "Детекторы"),
    ("contradictions", "Противоречия"),
    ("allowlist",     "Allowlist"),
    ("dga",           "DGA"),
    ("brute",         "Brute force"),
    ("network",       "Сеть"),
    ("reports",       "Отчёты"),
    ("plugins",       "Плагины"),
    ("yara", "YARA"),
    ("threatintel",   "Threat Intel"),
    ("perf",          "Производительность"),
)

_DETECTORS = (
    ("dga",                "DGA — домены-генераторы"),
    ("port_scan",          "Port scan"),
    ("suspicious_port",    "Suspicious port"),
    ("nxdomain_burst",     "NXDOMAIN burst"),
    ("cloud_tunnel",       "Cloud tunnel"),
    ("ip_check_service",   "IP check service"),
    ("typosquatting",      "Typosquatting"),
    ("sni_mismatch",       "SNI mismatch"),
    ("rare_external_ip",   "Rare external IP"),
    ("long_connections",   "Long connections"),
    ("ja3_malware",        "JA3 malware"),
    ("ja3s_malware",       "JA3S malware"),
    ("brute_force",        "Brute force (HTTP)"),
    ("ftp_brute_force",    "FTP brute force"),
    ("beaconing",          "Beaconing"),
    ("dns_tunneling",      "DNS tunneling"),
    ("lateral_movement",   "Lateral movement"),
    ("large_transfer",     "Large transfer"),
    ("vulnerable_path",    "Vulnerable path"),
    ("command_injection",  "Command injection"),
    ("http_binary_upload", "HTTP binary upload"),
    ("php_payload",        "PHP payload / webshell"),
    ("webshell_markers",   "Web shell markers"),
    ("ssh_brute_force", "SSH brute force"),
    ("smtp_spam", "SMTP spam"),
    ("yara", "YARA"),
)

# 12 правил из paradox/contradictions/rules/.
# Ключ — имя класса; analysis_worker фильтрует по type(r).__name__.
_CONTRADICTIONS = (
    ("VictimMakesAttackRule",   "victim_makes_attack (PIVOT) — critical"),
    ("MacIpConflictRule",       "mac_ip_conflict (ARP-spoof) — critical"),
    ("SniHostMismatchRule",     "sni_host_mismatch (fronting) — high"),
    ("Ja3UaMismatchRule",       "ja3_ua_mismatch (UA spoof) — high"),
    ("ReverseAsymmetryRule",    "reverse_asymmetry (exfil) — medium"),
    ("PortServiceMismatchRule", "port_service_mismatch (tunnel) — high"),
    ("DirectIpNoDnsRule",       "direct_ip_no_dns (hardcoded) — medium"),
    # v0.9.0: добавлены недостающие 5 правил
    ("SniWithoutDnsRule",       "sni_without_dns (SNI без DNS) — medium"),
    ("DnsAnswerMismatchRule",   "dns_answer_mismatch (подмена ответа) — medium"),
    ("SniCertMismatchRule",     "sni_cert_mismatch (CN/SAN ≠ SNI) — medium"),
    ("SelfSignedCertRule",      "self_signed_cert — medium"),
    ("ExpiredCertRule",         "expired_cert — low"),
)
