"""
MITRE ATT&CK mapping для детекторов Paradox.

Источник правды — `paradox/taxonomy.py`. Этот модуль оставлен как
стабильный импорт для детекторов и тестов.
"""
from paradox.taxonomy import MITRE_BY_TYPE, get_techniques

MITRE_MAP = MITRE_BY_TYPE

__all__ = ["MITRE_MAP", "get_techniques"]
