"""Smoke-тесты QuickCheckWindow (offscreen)."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_window_instantiates(qapp):
    from paradox.config import Config
    from paradox_gui.views.quick_check_window import QuickCheckWindow
    w = QuickCheckWindow(Config())
    assert w is not None


def test_autodetect_hint_ip(qapp):
    from paradox.config import Config
    from paradox_gui.views.quick_check_window import QuickCheckWindow
    w = QuickCheckWindow(Config())
    w._ioc_input.setText("8.8.8.8")
    assert "ip" in w._type_hint.text()


def test_autodetect_hint_empty(qapp):
    from paradox.config import Config
    from paradox_gui.views.quick_check_window import QuickCheckWindow
    w = QuickCheckWindow(Config())
    w._ioc_input.setText("")
    assert w._type_hint.text() == ""


def test_resolve_type_from_combo(qapp):
    from paradox.config import Config
    from paradox_gui.views.quick_check_window import QuickCheckWindow
    w = QuickCheckWindow(Config())
    w._type_combo.setCurrentText("domain")
    w._ioc_input.setText("evil.com")
    assert w._resolve_type() == "domain"


def test_clear_results_no_children(qapp):
    from paradox.config import Config
    from paradox_gui.views.quick_check_window import QuickCheckWindow
    w = QuickCheckWindow(Config())
    w._clear_results()
    # Только stretch в layout
    assert w._results_layout.count() == 1
