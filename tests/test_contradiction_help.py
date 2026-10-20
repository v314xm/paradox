"""Тесты описаний противоречий."""
from paradox_gui.contradiction_help import (
    CONTRADICTION_HELP,
    get_contradiction_help,
)
from paradox_gui.views.settings_view import _CONTRADICTIONS


def test_all_contradictions_have_help():
    missing = [k for k, _ in _CONTRADICTIONS if k not in CONTRADICTION_HELP]
    assert not missing, f"нет описаний для: {sorted(missing)}"


def test_no_extra_help_keys():
    known = {k for k, _ in _CONTRADICTIONS}
    extra = set(CONTRADICTION_HELP) - known
    assert not extra, f"лишние ключи: {sorted(extra)}"


def test_help_texts_not_empty():
    empty = [k for k, v in CONTRADICTION_HELP.items() if not v.strip()]
    assert not empty, f"пустые описания: {empty}"


def test_get_help_fallback():
    assert get_contradiction_help("nonexistent") == ""


def test_count_is_twelve():
    assert len(CONTRADICTION_HELP) == 12
