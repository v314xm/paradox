"""
Общие сетевые утилиты.

Используются в reporters, aggregators и противоречиях для
классификации IP и направления трафика.
"""
from __future__ import annotations

import ipaddress

from paradox.config import Config

# Базовые непубличные диапазоны. Config.private_networks повторяет
# большинство из них строковыми префиксами; здесь — канонический
# разбор через ipaddress, чтобы не зависеть от регистра и формы
# записи IPv6 (FE80::1, ::ffff:10.0.0.1).
_INTERNAL_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",     # CGNAT
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
))
_INTERNAL_V6 = tuple(ipaddress.ip_network(n) for n in (
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
))


def _config_prefix_match(addr, config: Config) -> bool:
    """Совпадение с Config.private_networks (строковые префиксы)."""
    candidates = {addr.compressed.lower(), str(addr).lower()}
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        candidates.add(mapped.compressed.lower())
        candidates.add(str(mapped).lower())

    for raw in config.private_networks:
        prefix = raw.strip().lower()
        if prefix and any(c.startswith(prefix) for c in candidates):
            return True
    return False


def ip_scope(ip: str, config: Config | None = None) -> str:
    """Классифицировать адрес: ``internal``, ``external`` или ``special``.

    ``special`` — не IP-адрес вообще (пустая строка, битое значение).
    ``internal`` — приватный, loopback, link-local, multicast,
    CGNAT, reserved или диапазон из ``config.private_networks``.
    Всё остальное — ``external``.
    """
    if not isinstance(ip, str) or not ip.strip():
        return "special"
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return "special"

    if config is not None and _config_prefix_match(addr, config):
        return "internal"

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    nets = _INTERNAL_V4 if isinstance(addr, ipaddress.IPv4Address) else _INTERNAL_V6
    if any(addr in net for net in nets):
        return "internal"
    return "external"


def is_private_ip(ip: str, config: Config | None = None) -> bool:
    """Непубличный адрес. Конфиг опционален для совместимости."""
    return ip_scope(ip, config) == "internal"


def is_internal_ip(ip: str, config: Config) -> bool:
    """Внутренний адрес с учётом пользовательских сетей из Config."""
    return ip_scope(ip, config) == "internal"


def is_public_ip(ip: str, config: Config | None = None) -> bool:
    """Публичный (external) адрес; ``special`` сюда не попадает."""
    return ip_scope(ip, config) == "external"


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
