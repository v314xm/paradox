"""Тесты подсказок справа от полей."""
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


def test_field_hints_dict_exists(view):
    assert hasattr(view, "_field_hints")
    assert len(view._field_hints) > 0


def test_threshold_field_has_hint(view):
    key = "nxdomain_burst_window_sec"
    assert key in view._field_hints
    hint = view._field_hints[key]
    assert hint.text()
    assert "окно" in hint.text().lower() or "сек" in hint.text().lower()


def test_beaconing_field_hint_mentions_signal(view):
    hint = view._field_hints.get("beaconing_min_connections")
    assert hint is not None
    assert "beaconing" in hint.text().lower() or "соедин" in hint.text().lower()


def test_brute_force_hint_exists(view):
    assert "brute_force_min_unique_src_ports" in view._field_hints


def test_performance_hint_exists(view):
    assert "tcp_reassembly_enabled" in view._field_hints


def test_hint_has_tooltip(view):
    hint = view._field_hints["nxdomain_burst_window_sec"]
    assert hint.toolTip() == hint.text()
