"""Тесты описаний детекторов."""
from paradox_gui.detector_help import DETECTOR_HELP, get_detector_help
from paradox_gui.views.settings_view import _DETECTORS


def test_all_detectors_have_help():
    missing = [k for k, _ in _DETECTORS if k not in DETECTOR_HELP]
    assert not missing, f"нет описаний для: {sorted(missing)}"


def test_no_extra_help_keys():
    known = {k for k, _ in _DETECTORS}
    extra = set(DETECTOR_HELP) - known
    assert not extra, f"лишние ключи: {sorted(extra)}"


def test_help_texts_not_empty():
    empty = [k for k, v in DETECTOR_HELP.items() if not v.strip()]
    assert not empty, f"пустые описания: {empty}"


def test_get_detector_help_fallback():
    assert get_detector_help("nonexistent_key") == ""


def test_help_and_settings_are_in_sync():
    """_DETECTORS (settings_view) и DETECTOR_HELP (help) должны быть синхронны.

    Ловит две ошибки:
      - добавили детектор в GUI — забыли описание;
      - добавили описание — забыли детектор.
    """
    settings_keys = {k for k, _ in _DETECTORS}
    help_keys = set(DETECTOR_HELP)

    missing_in_help = settings_keys - help_keys
    missing_in_settings = help_keys - settings_keys

    assert not missing_in_help, (
        f"нет описаний для: {sorted(missing_in_help)}"
    )
    assert not missing_in_settings, (
        f"описания без детектора: {sorted(missing_in_settings)}"
    )
