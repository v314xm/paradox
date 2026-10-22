"""
Fix #5: создай два страж-теста.

  1. tests/test_severity_map.py      — все типы от детекторов должны
                                       быть в _SEVERITY_BY_TYPE
  2. tests/test_gui_severity_sync.py — severity в GUI-лейблах должна
                                       совпадать с rule.severity_base

Оба ловят класс регрессий, а не единичный баг. Если в будущем появится
новый детектор или правило — тесты упадут с явным списком missing.

Идемпотентно: существующие файлы не перезаписываются.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"


# ВНИМАНИЕ: r'''...''' — потому что внутри есть \s в regex.
# Одинарным r-string (\s → \s) добиваемся, чтобы в сгенерированном
# файле был regex \s, а не литерал '\s' в f-string.
TEST_SEVERITY_MAP = r'''"""Страж: все типы findings из детекторов должны быть в _SEVERITY_BY_TYPE."""
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
'''


TEST_GUI_SEVERITY_SYNC = r'''"""Страж: severity в GUI-лейблах правил должна совпадать с ядром."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import re

from paradox.contradictions.registry import RULES
from paradox_gui.views.settings_view import _CONTRADICTIONS


_SEVERITY_LABEL = re.compile(r'^.+?\s+—\s+(critical|high|medium|low|info)$')


def test_gui_severity_matches_core():
    """Для каждого правила GUI-лейбл должен заканчиваться на core severity."""
    core = {type(r).__name__: r.severity_base for r in RULES}
    mismatches: list[str] = []

    for name, label in _CONTRADICTIONS:
        m = _SEVERITY_LABEL.search(label)
        assert m, f"нет severity в лейбле: {name!r} → {label!r}"
        gui_sev = m.group(1)
        assert name in core, f"правило {name!r} не найдено в ядре"
        if gui_sev != core[name]:
            mismatches.append(
                f"{name}: GUI={gui_sev!r}  core={core[name]!r}"
            )

    assert not mismatches, (
        "Расхождение severity GUI ↔ ядро:\n  "
        + "\n  ".join(mismatches)
        + "\nЗапусти tools/sync_gui_severity.py."
    )


def test_gui_covers_all_core_rules():
    """Все правила из ядра должны быть представлены в GUI."""
    core_names = {type(r).__name__ for r in RULES}
    gui_names = {name for name, _ in _CONTRADICTIONS}
    missing = core_names - gui_names
    assert not missing, (
        f"правила без GUI-записи: {sorted(missing)}. "
        f"Добавь в _CONTRADICTIONS в settings_view.py."
    )


def test_gui_has_no_orphan_rules():
    """GUI не должен ссылаться на правила, которых нет в ядре."""
    core_names = {type(r).__name__ for r in RULES}
    gui_names = {name for name, _ in _CONTRADICTIONS}
    orphans = gui_names - core_names
    assert not orphans, (
        f"GUI ссылается на несуществующие правила: {sorted(orphans)}"
    )
'''


def main() -> int:
    TESTS_DIR.mkdir(exist_ok=True)
    created = 0

    for filename, content in (
        ("test_severity_map.py", TEST_SEVERITY_MAP),
        ("test_gui_severity_sync.py", TEST_GUI_SEVERITY_SYNC),
    ):
        path = TESTS_DIR / filename
        if path.exists():
            print(f"[SKIP] {path.relative_to(REPO_ROOT)} already exists")
            continue
        path.write_text(content, encoding="utf-8")
        print(f"[OK] создан {path.relative_to(REPO_ROOT)}")
        created += 1

    if not created:
        print("[SKIP] все тестовые файлы уже существуют")
    return 0


if __name__ == "__main__":
    sys.exit(main())
