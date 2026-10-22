# tools/fix_05_dedup_field_declarations.py
"""Remove duplicate field declarations left by manual merge.

- paradox/timeline.py: TimelineEvent.src_ip/dst_ip/dst_port ×2
- paradox/parsers.py:  PacketRecord.ipv6_meta ×3

Annotations in a dataclass are a dict; duplicates silently collapse to
the last one. Harmless at runtime but misleading when debugging and
trip some linters.
"""
from __future__ import annotations
from pathlib import Path

from fix_utils import patch

FIX_ID = "05-dedup-field-decls"
TITLE = "Убрать дублирующиеся объявления полей"

_TIMELINE_REL = "paradox/timeline.py"
_TIMELINE_OLD = '''    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
'''
_TIMELINE_NEW = '''    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
'''

_PARSERS_REL = "paradox/parsers.py"
_PARSERS_OLD = '''    # Метаданные IPv6 (extension chain, fragment info)
    ipv6_meta: dict | None = None

    # Метаданные IPv6 (extension chain, fragment info)
    ipv6_meta: dict | None = None

    # Метаданные IPv6 (extension chain, fragment info)
    ipv6_meta: dict | None = None
'''
_PARSERS_NEW = '''    # Метаданные IPv6 (extension chain, fragment info)
    ipv6_meta: dict | None = None
'''


def apply(root: Path) -> bool:
    changed = False
    if patch(root, _TIMELINE_REL, _TIMELINE_OLD, _TIMELINE_NEW, required=False):
        changed = True
    if patch(root, _PARSERS_REL, _PARSERS_OLD, _PARSERS_NEW, required=False):
        changed = True
    return changed
