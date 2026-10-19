"""Тесты описаний детекторов."""
from pcap_triage_gui.detector_help import DETECTOR_HELP, get_detector_help
from pcap_triage_gui.views.settings_view import _DETECTORS


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


def test_count_is_seventeen():
    assert len(DETECTOR_HELP) == 17
