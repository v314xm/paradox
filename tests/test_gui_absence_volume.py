"""GUI: вкладка «Объём по хостам» в панели аномалий."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui

MB = 1024 * 1024


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _host(ip: str, up: int = 0, down: int = 0,
          flows_out: int = 0, flows_in: int = 0) -> dict:
    return {
        "ip": ip,
        "roles": ["victim_candidate"],
        "bytes_out": up,
        "bytes_in": down,
        "flows_out": flows_out,
        "flows_in": flows_in,
    }


def _report(internal: list[dict]) -> dict:
    return {
        "absence": {"dns_unanswered": [], "tcp_unanswered": []},
        "entities": {"internal": internal},
    }


def test_volume_tab_sorts_flags_and_shows_share(qapp):
    from paradox_gui.widgets.absence_panel import AbsencePanel

    panel = AbsencePanel()
    panel.update_report(_report([
        _host("10.0.0.5", up=100 * MB, down=2 * MB,
              flows_out=50, flows_in=10),
        _host("10.0.0.6", up=1 * MB, down=1 * MB),
        _host("10.0.0.7", up=200 * 1024, down=100 * 1024),
    ]))

    assert panel.isHidden() is False
    assert panel.tabs.currentIndex() == 2, "единственная вкладка с данными"
    assert panel.table_volume.rowCount() == 3

    assert panel.table_volume.item(0, 0).text() == "10.0.0.5"
    assert panel.table_volume.item(0, 1).text() == "100.0 МБ"
    assert panel.table_volume.item(0, 2).text() == "2.0 МБ"
    assert panel.table_volume.item(0, 3).text() == "99%"
    assert panel.table_volume.item(0, 5).text().startswith("выброс ×")

    assert panel.table_volume.item(1, 0).text() == "10.0.0.6"
    assert panel.table_volume.item(1, 5).text() == "", "не выброс"


def test_volume_tab_hidden_without_entities(qapp):
    from paradox_gui.widgets.absence_panel import AbsencePanel

    panel = AbsencePanel()
    panel.update_report({
        "absence": {
            "dns_unanswered": [{"qname": "a.example", "count": 1}],
            "tcp_unanswered": [],
        },
        "entities": {},
    })

    assert panel.isHidden() is False
    assert panel.tabs.isTabVisible(panel._volume_tab_index) is False
    assert panel.tabs.currentIndex() == 0

    panel.clear()
    assert panel.isHidden() is True
    assert panel.tabs.isTabVisible(panel._volume_tab_index) is False
    assert panel.table_volume.rowCount() == 0


def test_double_click_emits_host_story(qapp):
    from PySide6.QtTest import QSignalSpy

    from paradox_gui.widgets.absence_panel import AbsencePanel

    panel = AbsencePanel()
    panel.update_report(_report([
        _host("10.0.0.5", up=10 * MB),
    ]))

    spy = QSignalSpy(panel.host_story_requested)
    panel.table_volume.cellDoubleClicked.emit(0, 0)
    assert spy.count() == 1
    assert spy.at(0)[0] == "10.0.0.5"
