"""f09: убрать эвристику «.0/.255 → broadcast» в _is_special_ip.

Для сетей крупнее /24 эта эвристика ошибочна:
  - 10.0.0.0/23: хосты 10.0.0.1..10.0.0.254 и 10.0.1.0..10.0.1.254
  - 10.0.1.255 — валидный хост (broadcast /23 = 10.0.1.255 — только
    если сеть /23, и тогда это broadcast; но если /22 — валидный хост)

Без маски в руках гадать нельзя. Убираем — is_multicast, is_loopback,
is_link_local, is_unspecified, is_reserved достаточно для типичного
шума. Если попадётся broadcast — аналитик разберётся (или allowlist).
"""
from pathlib import Path

from tools._patcher import assert_applied, assert_not_present, patch

NAME = "f09: entities.py — без .0/.255 эвристики"
FILES = ["paradox/aggregators/entities.py"]

_OLD = '''def _is_special_ip(ip: str) -> bool:
    """Multicast, broadcast, loopback, link-local — не сущности."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return True
    if addr.is_multicast or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_unspecified or addr.is_reserved:
        return True
    if str(addr) == "255.255.255.255":
        return True
    if addr.version == 4:
        last_octet = int(str(addr).rsplit(".", 1)[1])
        if last_octet == 0 or last_octet == 255:
            return True
    return False'''

_NEW = '''def _is_special_ip(ip: str) -> bool:
    """Multicast, broadcast, loopback, link-local — не сущности.

    v1.4: убрали эвристику «последний октет == 0 или 255». Для
    сетей крупнее /24 она ошибочна: в 10.0.0.0/23 хост 10.0.1.255 —
    валидный. Без маски подсети в руках гадать нельзя, поэтому
    оставляем только то, что ipaddress знает про отдельный адрес:
    is_multicast / is_loopback / is_link_local / is_unspecified /
    is_reserved. Плюс явный broadcast-литерал 255.255.255.255.
    """
    try:
        addr = ip_address(ip)
    except ValueError:
        return True
    if addr.is_multicast or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_unspecified or addr.is_reserved:
        return True
    if str(addr) == "255.255.255.255":
        return True
    return False'''


def apply(root: Path) -> bool:
    return patch(root, FILES[0], _OLD, _NEW)


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], "v1.4: убрали эвристику")
    assert_not_present(root, FILES[0], "last_octet = int(str(addr)")
