"""
Общие сетевые утилиты.

Используются в reporters и aggregators для классификации IP
и направления трафика.
"""
import ipaddress

from paradox.config import Config


def is_private_ip(ip: str) -> bool:
    """Приватный / loopback / link-local / multicast / CGNAT."""
    if not isinstance(ip, str) or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return True
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network('100.64.0.0/10'):
        return True
    return False


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
