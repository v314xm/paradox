"""Страж единой таксономии findings.

Все типы, которые умеют выдавать детекторы, должны быть описаны
в paradox/taxonomy.py: severity, полярность, MITRE, фаза и порядок
в TL;DR. Иначе снова появятся расходящиеся копии таблиц.
"""
import re
from pathlib import Path

from paradox.taxonomy import (
    CHAIN_ORDER,
    MITRE_BY_TYPE,
    PHASE_BY_TYPE,
    PHASE_ORDER,
    SEVERITY_BY_TYPE,
    SRC_ROLE_BY_TYPE,
)

_DETECTORS_DIR = Path(__file__).resolve().parent.parent / "paradox" / "detectors"
_SKIP_FILES = frozenset({
    "__init__.py",
    "base.py",
    "explainer.py",
    "mitre_map.py",
})

_TYPE_LITERAL = re.compile(r'^\s*type\s*=\s*"([a-z_]+)"', re.M)
_KIND_LITERAL = re.compile(r'^\s*kind\s*=\s*"([a-z_]+)"', re.M)
_KINDS_APPEND = re.compile(r'^\s*kinds\.append\("([a-z_]+)"\)', re.M)

# Типы без роли по замыслу: статистика объёма и событие timeline.
_NO_ROLE_TYPES = frozenset({"large_transfer", "carved_file"})


def _collect_detector_types() -> set[str]:
    types: set[str] = set()
    for py_file in _DETECTORS_DIR.glob("*.py"):
        if py_file.name in _SKIP_FILES:
            continue
        text = py_file.read_text(encoding="utf-8")
        for pattern in (_TYPE_LITERAL, _KIND_LITERAL, _KINDS_APPEND):
            types.update(pattern.findall(text))
    return types


def test_detector_types_are_in_taxonomy():
    types = _collect_detector_types()
    assert types, "regex не нашёл ни одного типа — проверь шаблоны"

    missing = []
    for t in sorted(types):
        for name, table in (
            ("SEVERITY_BY_TYPE", SEVERITY_BY_TYPE),
            ("MITRE_BY_TYPE", MITRE_BY_TYPE),
            ("PHASE_BY_TYPE", PHASE_BY_TYPE),
            ("CHAIN_ORDER", CHAIN_ORDER),
        ):
            if t not in table:
                missing.append(f"{t} → {name}")
        if t not in SRC_ROLE_BY_TYPE and t not in _NO_ROLE_TYPES:
            missing.append(f"{t} → SRC_ROLE_BY_TYPE")

    assert not missing, "типы findings не описаны в taxonomy.py:\n  " + "\n  ".join(missing)


def test_every_phase_is_ordered():
    unknown = {p for p in PHASE_BY_TYPE.values() if p not in PHASE_ORDER}
    assert not unknown, f"фазы без порядка: {unknown}"


def test_roles_are_only_attacker_or_victim():
    allowed = {"attacker", "victim"}
    bad = {t: r for t, r in SRC_ROLE_BY_TYPE.items() if r not in allowed}
    assert not bad, f"недопустимые роли: {bad}"


def test_severity_values_are_known():
    allowed = {"critical", "high", "medium", "low", "info"}
    bad = {t: s for t, s in SEVERITY_BY_TYPE.items() if s not in allowed}
    assert not bad, f"неизвестная severity: {bad}"


def test_finding_severity_defaults_from_map():
    """Детектор не задал severity — берётся значение из карты."""
    from paradox.models import Finding

    finding = Finding(type="webshell_upload", value="x", confidence=0.9)

    assert finding.severity == SEVERITY_BY_TYPE["webshell_upload"]


def test_explicit_medium_severity_wins_over_map():
    """Явный "medium" не перетирается картой (раньше это было невозможно)."""
    from paradox.models import Finding

    finding = Finding(
        type="webshell_upload", value="x", confidence=0.9, severity="medium",
    )

    assert finding.severity == "medium"


def test_outbound_exfil_marks_src_as_victim():
    """Исходящая загрузка — жертва отдаёт данные, а не атакует."""
    from paradox.contradictions.facts import extract_attack_facts
    from paradox.models import Finding

    finding = Finding(
        type="http_binary_upload",
        value="10.0.0.5 → evil.example",
        confidence=0.7,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.9",
    )
    facts = extract_attack_facts([finding])
    pairs = {(f.subject, f.predicate) for f in facts}

    assert ("10.0.0.5", "victim_of") in pairs
    assert ("203.0.113.9", "attacker_of") in pairs
    assert ("10.0.0.5", "attacker_of") not in pairs


def test_pivot_subjects_filters_by_rule():
    """Pivot собирается одним помощником для entities и attack_graph."""
    from paradox.taxonomy import pivot_subjects

    class _Contradiction:
        def __init__(self, rule: str, subject: str) -> None:
            self.rule = rule
            self.subject = subject

    contradictions = [
        _Contradiction("victim_makes_attack", "10.0.0.5"),
        _Contradiction("mac_ip_conflict", "10.0.0.6"),
    ]

    assert pivot_subjects(contradictions) == {"10.0.0.5"}
    assert pivot_subjects(None) == set()
