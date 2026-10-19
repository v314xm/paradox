"""Smoke: бейдж «изменено» и счётчик невалидных токенов."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_modified_badge_appears_on_change(qapp, tmp_path):
    from pcap_triage.config import Config
    from pcap_triage_gui.settings_store import SettingsStore
    from pcap_triage_gui.views.settings_view import SettingsView

    store = SettingsStore(tmp_path / "s.json")
    view = SettingsView(store=store)

    defaults = Config()
    key = "nxdomain_burst_window_sec"
    widget = view._threshold_inputs[key]

    assert widget.styleSheet() == "", "при дефолте стиль должен быть пуст"
    widget.setValue(defaults.nxdomain_burst_window_sec + 1)
    view._check_modified()
    assert "color" in widget.styleSheet(), "изменённое поле не подсвечено"
    widget.setValue(defaults.nxdomain_burst_window_sec)
    view._check_modified()
    assert widget.styleSheet() == "", "возврат к дефолту не снял подсветку"


def test_parse_ports_with_report_counts_invalid():
    from pcap_triage_gui.views.settings_view import _parse_ports_with_report

    parsed, skipped = _parse_ports_with_report("80, 443, abc, 99999, 8080")
    assert parsed == frozenset({80, 443, 8080})
    assert "abc" in skipped
    assert "99999" in skipped


def test_notify_status_sets_text(qapp, tmp_path):
    from pcap_triage_gui.settings_store import SettingsStore
    from pcap_triage_gui.views.settings_view import SettingsView

    store = SettingsStore(tmp_path / "s.json")
    view = SettingsView(store=store)
    view._notify_status("hi", level="warn")
    assert view._status_label.text() == "hi"


def test_status_label_exists_after_init(qapp, tmp_path):
    from pcap_triage_gui.settings_store import SettingsStore
    from pcap_triage_gui.views.settings_view import SettingsView

    store = SettingsStore(tmp_path / "s.json")
    view = SettingsView(store=store)
    assert hasattr(view, "_status_label")
