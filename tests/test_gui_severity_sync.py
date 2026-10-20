"""Страж: severity в GUI-лейблах правил должна совпадать с ядром."""
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
