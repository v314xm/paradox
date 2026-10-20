"""Smoke: SettingsView реально инстанцируется.

Ловит ошибки порядка инициализации, которые не видны без QApplication.
QT_QPA_PLATFORM=offscreen — без реального окна.
"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_settings_view_instantiates(qapp, tmp_path):
    from paradox_gui.settings_store import SettingsStore
    from paradox_gui.views.settings_view import SettingsView

    store = SettingsStore(tmp_path / "settings.json")
    view = SettingsView(store=store)
    assert view is not None
    # Ключевые атрибуты после __init__
    assert hasattr(view, "_active_profile_key")
    assert hasattr(view, "_profile_combo")
    assert hasattr(view, "_threshold_inputs")
    assert hasattr(view, "_detector_boxes")


def test_run_view_instantiates(qapp, tmp_path):
    from paradox_gui.settings_store import SettingsStore
    from paradox_gui.views.run_view import RunView

    store = SettingsStore(tmp_path / "settings.json")
    view = RunView(store=store)
    assert view is not None


def test_settings_view_tooltips_present(qapp, tmp_path):
    from paradox_gui.settings_store import SettingsStore
    from paradox_gui.views.settings_view import SettingsView

    store = SettingsStore(tmp_path / "settings.json")
    view = SettingsView(store=store)
    # Хотя бы у одного поля порогов должен быть tooltip.
    tips = [w.toolTip() for w in view._threshold_inputs.values()]
    assert any(tips), "ни у одного поля порогов нет tooltip"
