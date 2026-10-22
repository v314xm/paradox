from pathlib import Path

from fix_utils import patch

FIX_ID = "fix_20"
TITLE = "Add ipv6_meta to PacketRecord dataclass"

def apply(root: Path) -> bool:
    changed = False
    changed |= patch(
        root, "paradox/parsers.py",
        old=(
            "    # L4-payload (или сырые байты для не-первых IPv4-фрагментов)\n"
            "    payload: bytes = b\"\"\n"
        ),
        new=(
            "    # L4-payload (или сырые байты для не-первых IPv4-фрагментов)\n"
            "    payload: bytes = b\"\"\n\n"
            "    # Метаданные IPv6 (extension chain, fragment info)\n"
            "    ipv6_meta: dict | None = None\n"
        )
    )
    changed |= patch(
        root, "paradox/parsers.py",
        old=(
            "        if hasattr(ipv6_rec, \"ipv6_meta\"):\n"
            "            object.__setattr__(rec, \"ipv6_meta\", ipv6_rec.ipv6_meta)\n"
        ),
        new=(
            "        rec.ipv6_meta = getattr(ipv6_rec, \"ipv6_meta\", None)\n"
        )
    )
    return changed
