"""Markdown-отчёт: mitre."""
from __future__ import annotations

from paradox.taxonomy import mitre_label


def _mitre_for_finding(f: dict) -> str:
    """
    Instance-level mitre_techniques приоритетнее type-map.

    large_transfer знает про T1041/T1105 сам (по direction),
    а таксономия знает только общий T1041.
    """
    techniques = f.get("mitre_techniques") or ()
    if techniques:
        return ", ".join(techniques)
    return mitre_label(str(f.get("type", "")))
