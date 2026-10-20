"""Страж: все типы findings из детекторов должны быть в _SEVERITY_BY_TYPE."""
import re
from pathlib import Path

from paradox.models import _SEVERITY_BY_TYPE


_DETECTORS_DIR = Path(__file__).resolve().parent.parent / "paradox" / "detectors"
_TYPE_LITERAL = re.compile(r'type\s*=\s*"([a-z_]+)"')

_SKIP_FILES = frozenset({
    "__init__.py",
    "base.py",
    "explainer.py",
    "mitre_map.py",
})


def _collect_detector_types() -> set[str]:
    """Все строки вида type=\"xxx\" из paradox/detectors/*.py."""
    types: set[str] = set()
    for py_file in _DETECTORS_DIR.glob("*.py"):
        if py_file.name in _SKIP_FILES:
            continue
        text = py_file.read_text(encoding="utf-8")
        for m in _TYPE_LITERAL.finditer(text):
            types.add(m.group(1))
    return types


def test_all_detector_types_in_severity_map():
    known = _collect_detector_types()
    missing = known - set(_SEVERITY_BY_TYPE)
    assert not missing, (
        "детекторы пишут типы без _SEVERITY_BY_TYPE:\n  "
        + "\n  ".join(sorted(missing))
        + "\nДобавь их в paradox/models.py → _SEVERITY_BY_TYPE."
    )


def test_sanity_types_found():
    """Проверка что regex не сломался и вообще что-то нашёл."""
    known = _collect_detector_types()
    assert len(known) >= 10, f"подозрительно мало типов: {known}"
    assert "brute_force" in known
    assert "beaconing" in known
