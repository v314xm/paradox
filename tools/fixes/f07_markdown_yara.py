"""f07: yara_match в markdown_reporter — _CHAIN_ORDER и _MITRE_MAP.

_CHAIN_ORDER: без него yara_match уезжает в _CHAIN_UNKNOWN=999,
TL;DR показывает YARA в самом конце (после large_transfer).
_MITRE_MAP: fallback, когда у finding'а нет mitre_techniques.
"""
from pathlib import Path

from tools._patcher import assert_applied, patch

NAME = "f07: markdown_reporter.py — yara_match в _CHAIN_ORDER/_MITRE_MAP"
FILES = ["paradox/reporters/markdown_reporter.py"]

_OLD_CHAIN = '''    "script_download":   60,
    "carved_file":       65,
    "suspicious_port":   70,'''

_NEW_CHAIN = '''    "script_download":   60,
    "carved_file":       65,
    "yara_match":        67,
    "suspicious_port":   70,'''

_OLD_MITRE = '''    "suspicious_port":    "T1571 (Non-Standard Port)",
    "carved_file":        "T1105 (Ingress Tool Transfer)",
}'''

_NEW_MITRE = '''    "suspicious_port":    "T1571 (Non-Standard Port)",
    "carved_file":        "T1105 (Ingress Tool Transfer)",
    "yara_match":         "T1204 (User Execution)",
}'''


def apply(root: Path) -> bool:
    changed = False
    changed |= patch(root, FILES[0], _OLD_CHAIN, _NEW_CHAIN)
    changed |= patch(root, FILES[0], _OLD_MITRE, _NEW_MITRE)
    return changed


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], '"yara_match":        67,')
    assert_applied(root, FILES[0], '"yara_match":         "T1204 (User Execution)",')
