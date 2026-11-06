"""
GUI: секция «Плагины» в настройках.

Проверяем, что страница существует, показывает статус и отдаёт
plugins_enabled/plugins_dir в config_applied.
"""
import os
import textwrap

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _view(tmp_path):
    from paradox_gui.settings_store import SettingsStore
    from paradox_gui.views.settings_view import SettingsView

    return SettingsView(store=SettingsStore(tmp_path / "settings.json"))


def _plugin_source():
    return textwrap.dedent(
        """
        class DemoDetector:
            name = "demo_plugin"

            def run(self, state, config):
                return []


        DETECTORS = [DemoDetector()]
        """
    )


def test_plugins_page_exists(qapp, tmp_path):
    view = _view(tmp_path)
    assert hasattr(view, "_plugins_enabled")
    assert hasattr(view, "_plugins_dir")
    assert hasattr(view, "_plugins_status")


def test_plugins_disabled_by_default(qapp, tmp_path):
    from paradox_gui.i18n import tr

    view = _view(tmp_path)
    assert view._plugins_enabled.isChecked() is False
    assert view._plugins_status.text() == tr("settings.plugins.off")


def test_plugins_check_reports_loaded_detector(qapp, tmp_path):
    from paradox_gui.i18n import tr

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "demo.py").write_text(
        _plugin_source(), encoding="utf-8",
    )

    view = _view(tmp_path)
    view._plugins_enabled.setChecked(True)
    view._plugins_dir.setText(str(plugin_dir))
    view._check_plugins()

    text = view._plugins_status.text()
    assert tr("settings.plugins.loaded") in text
    assert "demo_plugin" in text


def test_plugins_check_missing_dir(qapp, tmp_path):
    from paradox_gui.i18n import tr

    view = _view(tmp_path)
    view._plugins_enabled.setChecked(True)
    view._plugins_dir.setText(str(tmp_path / "absent"))
    view._check_plugins()

    assert tr("settings.plugins.missing") in view._plugins_status.text()


def test_apply_emits_plugins_overrides(qapp, tmp_path):
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()

    view = _view(tmp_path)
    captured = []
    view.config_applied.connect(captured.append)

    view._plugins_enabled.setChecked(True)
    view._plugins_dir.setText(str(plugin_dir))
    view._apply_plugins()

    assert captured
    values = captured[-1]
    assert values["plugins_enabled"] is True
    assert values["plugins_dir"] == plugin_dir
