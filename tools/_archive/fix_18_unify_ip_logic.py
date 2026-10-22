from pathlib import Path

from fix_utils import patch

FIX_ID = "fix_18"
TITLE = "Consolidate private IP logic in net_utils + fix CGNAT"

def apply(root: Path) -> bool:
    changed = False
    # 1. net_utils
    changed |= patch(
        root, "paradox/net_utils.py",
        old="from paradox.config import Config\n\n\ndef is_internal_ip(ip: str, config: Config) -> bool:\n",
        new=(
            "import ipaddress\n"
            "from paradox.config import Config\n\n\n"
            "def is_private_ip(ip: str) -> bool:\n"
            "    \"\"\"Приватный / loopback / link-local / multicast / CGNAT.\"\"\"\n"
            "    if not isinstance(ip, str) or not ip:\n"
            "        return False\n"
            "    try:\n"
            "        addr = ipaddress.ip_address(ip)\n"
            "    except ValueError:\n"
            "        return False\n"
            "    if addr.is_private or addr.is_loopback or addr.is_link_local:\n"
            "        return True\n"
            "    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:\n"
            "        return True\n"
            "    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network('100.64.0.0/10'):\n"
            "        return True\n"
            "    return False\n\n\n"
            "def is_internal_ip(ip: str, config: Config) -> bool:\n"
        )
    )
    # 2. enricher.py
    changed |= patch(
        root, "paradox/integrations/enricher.py",
        old="import ipaddress\n\nfrom paradox.config import Config\n",
        new="from paradox.config import Config\n"
    )
    changed |= patch(
        root, "paradox/integrations/enricher.py",
        old=(
            "_CGNAT_V4 = ipaddress.ip_network(\"100.64.0.0/10\")\n\n\n"
            "def _is_private_ip(ip: str) -> bool:\n"
            "    \"\"\"\n"
            "    Приватный / loopback / link-local / multicast / CGNAT / IPv6.\n\n"
            "    Python 3.13: is_private для 100.64/10 = False, поэтому CGNAT\n"
            "    проверяем явно.\n"
            "    \"\"\"\n"
            "    if not isinstance(ip, str) or not ip:\n"
            "        return False\n"
            "    try:\n"
            "        addr = ipaddress.ip_address(ip)\n"
            "    except ValueError:\n"
            "        return False\n"
            "    if addr.is_private or addr.is_loopback or addr.is_link_local:\n"
            "        return True\n"
            "    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:\n"
            "        return True\n"
            "    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_V4:\n"
            "        return True\n"
            "    return False\n"
        ),
        new="from paradox.net_utils import is_private_ip as _is_private_ip\n"
    )
    # 3. lateral_movement.py
    changed |= patch(
        root, "paradox/detectors/lateral_movement.py",
        old="    def _is_internal(self, ip: str, config: Config) -> bool:\n        return any(ip.startswith(p) for p in config.private_networks)\n",
        new="    def _is_internal(self, ip: str, config: Config) -> bool:\n        from paradox.net_utils import is_internal_ip\n        return is_internal_ip(ip, config)\n"
    )
    # 4. export_view.py
    changed |= patch(
        root, "paradox_gui/views/export_view.py",
        old="import ipaddress\n",
        new="",
    )
    changed |= patch(
        root, "paradox_gui/views/export_view.py",
        old="def _is_private_ip(ip_str: str) -> bool:\n    try:\n        return ipaddress.ip_address(ip_str).is_private\n    except ValueError:\n        return False\n",
        new="def _is_private_ip(ip_str: str) -> bool:\n    from paradox.net_utils import is_private_ip\n    return is_private_ip(ip_str)\n"
    )
    return changed
