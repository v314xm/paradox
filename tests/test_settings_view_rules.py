"""Регрессия: правила ContradictionDetector в GUI должны покрывать ядро.

Если в ядре появится новое правило, а в _CONTRADICTIONS его забудут,
тест упадёт с явным списком missing.
"""
import re
from pathlib import Path

from pcap_triage_gui.views.settings_view import _CONTRADICTIONS


CORE_RULES_DIR = Path(__file__).resolve().parent.parent / "pcap_triage" / "contradictions" / "rules"


def _core_rule_names() -> set[str]:
    """Все классы *Rule (кроме базового) в pcap_triage/contradictions/rules/."""
    names: set[str] = set()
    pat = re.compile(r"^\s*class\s+(\w+Rule)\s*[\(:]", re.MULTILINE)
    for p in CORE_RULES_DIR.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        text = p.read_text(encoding="utf-8")
        for m in pat.finditer(text):
            name = m.group(1)
            if name == "ContradictionRule":  # базовый — не правило
                continue
            names.add(name)
    return names


def _gui_rule_names() -> set[str]:
    return {name for name, _ in _CONTRADICTIONS}


def test_core_rules_dir_exists():
    assert CORE_RULES_DIR.is_dir(), f"не найден {CORE_RULES_DIR}"


def test_gui_covers_all_core_rules():
    core = _core_rule_names()
    gui = _gui_rule_names()
    missing = core - gui
    assert not missing, (
        f"В GUI нет правил: {sorted(missing)}. "
        f"Добавь их в _CONTRADICTIONS в settings_view.py."
    )


def test_gui_has_no_orphan_rules():
    core = _core_rule_names()
    gui = _gui_rule_names()
    orphans = gui - core
    assert not orphans, (
        f"В GUI есть правила, которых нет в ядре: {sorted(orphans)}. "
        f"Отключение таких правил молча промахнётся."
    )


def test_expected_count_is_twelve():
    # Фиксируем текущее состояние: 12 правил в ядре v0.9.0.
    assert len(_core_rule_names()) == 12


def test_nxdomain_window_in_thresholds_widget():
    """Проверяем, что параметр реально выведен в UI.

    Тянем исходник и ищем ключ в вызове _add_int_row / _add_float_row.
    Без инстанцирования Qt-виджета.
    """
    src = Path(__file__).resolve().parent.parent / "pcap_triage_gui" / "views" / "settings_view.py"
    text = src.read_text(encoding="utf-8")
    assert '"nxdomain_burst_window_sec"' in text, (
        "nxdomain_burst_window_sec не выведен в Пороги"
    )
    assert '"nxdomain_burst_min_ratio"' in text, (
        "nxdomain_burst_min_ratio не выведен в Пороги"
    )