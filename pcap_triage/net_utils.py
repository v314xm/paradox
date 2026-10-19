"""
Общие сетевые утилиты.

Используются в reporters и aggregators для классификации IP
и направления трафика.
"""
from pcap_triage.config import Config


def is_internal_ip(ip: str, config: Config) -> bool:
    """Приватный IP (RFC1918, IPv6 ULA/link-local, loopback, multicast)."""
    # Для IPv6 проверяем по префиксам (fc, fd, fe80, ::1)
    if ":" in ip:
        return ip.startswith("fc") or ip.startswith("fd") \
            or ip.startswith("fe80") or ip == "::1"
    # Для IPv4 — старый добрый startswith
    return any(ip.startswith(prefix) for prefix in config.private_networks)


def classify_direction(src_ip: str, dst_ip: str, config: Config) -> str:
    """
    Классификация направления трафика.

    Возвращает:
      "outbound" — src внутренний, dst внешний (upload)
      "inbound"  — src внешний, dst внутренний (download)
      "internal" — оба внутренние
      "external" — оба внешние (редко)
    """
    src_int = is_internal_ip(src_ip, config)
    dst_int = is_internal_ip(dst_ip, config)

    if src_int and not dst_int:
        return "outbound"
    if not src_int and dst_int:
        return "inbound"
    if src_int and dst_int:
        return "internal"
    return "external"