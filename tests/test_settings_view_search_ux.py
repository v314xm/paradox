"""Тесты UX поиска: Ctrl+F, Esc, hint."""
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


def test_search_has_tooltip(view):
    assert "Ctrl+F" in view._search_line.toolTip() or \
           "энциклоп" in view._search_line.toolTip().lower() or \
           "tooltip" in view._search_line.toolTip().lower()


def test_search_hint_label_exists(view):
    assert hasattr(view, "_search_hint")


def test_search_hint_shows_count(view):
    view._apply_search("beaconing")
    assert "Найдено" in view._search_hint.text()


def test_search_hint_cleared_on_empty(view):
    view._apply_search("beaconing")
    view._apply_search("")
    assert view._search_hint.text() == ""


def test_focus_search_selects_all(view):
    view._search_line.setText("abc")
    view._focus_search()
    assert view._search_line.selectedText() == "abc"


def test_escape_clears_search(view, qapp):
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    view._search_line.setText("beaconing")
    qapp.processEvents()
    ev = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier)
    view.eventFilter(view._search_line, ev)
    qapp.processEvents()
    assert view._search_line.text() == ""
