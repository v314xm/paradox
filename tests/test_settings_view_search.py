"""Smoke: поиск по настройкам."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def view(qapp, tmp_path):
    from paradox_gui.settings_store import SettingsStore
    from paradox_gui.views.settings_view import SettingsView
    return SettingsView(store=SettingsStore(tmp_path / "s.json"))


def test_search_line_exists(view):
    assert hasattr(view, "_search_line")


def test_search_signal_is_wired(qapp, view):
    """textChanged действительно подключён к _apply_search."""
    # Пишем в line, processEvents, ожидаем, что _search_text обновился.
    view._search_line.setText("beaconing")
    qapp.processEvents()
    # _apply_search сохраняет в self._search_text
    assert view._search_text == "beaconing"


def test_search_highlights_matching_field(view):
    view._apply_search("beaconing")
    w = view._threshold_inputs["beaconing_min_connections"]
    assert "background-color" in w.styleSheet()


def test_search_does_not_highlight_unrelated(view):
    view._apply_search("beaconing")
    w = view._threshold_inputs["nxdomain_burst_threshold"]
    assert "background-color" not in w.styleSheet()


def test_search_clear_removes_highlight(view):
    view._apply_search("beaconing")
    view._apply_search("")
    for key, w in view._threshold_inputs.items():
        assert "background-color" not in w.styleSheet(), key


def test_search_reports_count(view):
    view._apply_search("nxdomain")
    assert "Найдено" in view._status_label.text()


def test_search_matches_tooltip_text(view):
    """Поиск по тексту tooltip: 'энтроп' есть только в описании DGA."""
    view._apply_search("энтроп")
    w = view._threshold_inputs["dga_entropy_threshold"]
    assert "background-color" in w.styleSheet()
