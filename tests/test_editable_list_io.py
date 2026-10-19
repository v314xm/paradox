"""Тесты импорта/экспорта EditableListWidget."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def widget(qapp):
    from pcap_triage_gui.widgets.editable_list import EditableListWidget
    return EditableListWidget(port_mode=False)


@pytest.fixture
def port_widget(qapp):
    from pcap_triage_gui.widgets.editable_list import EditableListWidget
    return EditableListWidget(port_mode=True)


def test_parse_import_basic(widget):
    values, skipped = widget._parse_import_text("a\nb\nc")
    assert values == ["a", "b", "c"]
    assert skipped == 0


def test_parse_import_ignores_comments(widget):
    text = "# header\na\n\n# comment\nb"
    values, _ = widget._parse_import_text(text)
    assert values == ["a", "b"]


def test_parse_import_dedups(widget):
    values, _ = widget._parse_import_text("a\na\nb\nb")
    assert values == ["a", "b"]


def test_parse_import_csv_style(widget):
    values, _ = widget._parse_import_text("a, b, c")
    assert values == ["a", "b", "c"]


def test_parse_import_port_mode_filters_invalid(port_widget):
    values, skipped = port_widget._parse_import_text(
        "80\nabc\n443\n99999\n8080"
    )
    assert values == ["80", "443", "8080"]
    assert skipped == 2


def test_import_buttons_exist(widget):
    assert hasattr(widget, "_import_btn")
    assert hasattr(widget, "_export_btn")
    assert "Загрузить" in widget._import_btn.text()
    assert "Экспорт" in widget._export_btn.text()
