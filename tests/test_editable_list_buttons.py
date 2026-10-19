"""Дополнительные тесты: кнопки."""
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


def test_add_button_has_text(widget):
    assert widget._add_btn.text() == "Добавить"


def test_delete_button_has_text(widget):
    assert "Удалить" in widget._del_btn.text()


def test_delete_button_disabled_without_selection(widget):
    widget.setItems(["a", "b"])
    assert widget._del_btn.isEnabled() is False


def test_delete_button_enabled_on_selection(widget):
    widget.setItems(["a", "b"])
    widget._list.setCurrentRow(0)
    assert widget._del_btn.isEnabled() is True


def test_delete_button_disabled_after_removal(widget):
    widget.setItems(["a"])
    widget._list.setCurrentRow(0)
    widget._remove_selected()
    assert widget._del_btn.isEnabled() is False
