"""Тесты EditableListWidget."""
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
    from paradox_gui.widgets.editable_list import EditableListWidget
    return EditableListWidget(port_mode=False)


@pytest.fixture
def port_widget(qapp):
    from paradox_gui.widgets.editable_list import EditableListWidget
    return EditableListWidget(port_mode=True)


def test_empty_by_default(widget):
    assert widget.items() == []
    assert widget.toPlainText() == ""


def test_setplaintext_parses_newlines(widget):
    widget.setPlainText("a\nb\nc")
    assert widget.items() == ["a", "b", "c"]


def test_setplaintext_parses_commas(widget):
    widget.setPlainText("a, b, c")
    assert widget.items() == ["a", "b", "c"]


def test_setplaintext_dedups(widget):
    widget.setPlainText("a\na\nb")
    assert widget.items() == ["a", "b"]


def test_toplaintext_roundtrip(widget):
    widget.setPlainText("x\ny\nz")
    assert widget.toPlainText() == "x\ny\nz"


def test_add_valid_value(widget):
    widget._input.setText("hello")
    widget._add_from_input()
    assert widget.items() == ["hello"]
    assert widget._input.text() == ""


def test_add_rejects_duplicate(widget):
    widget.setItems(["a"])
    widget._input.setText("a")
    widget._add_from_input()
    assert widget.items() == ["a"]


def test_port_mode_rejects_non_numeric(port_widget):
    port_widget._input.setText("abc")
    port_widget._add_from_input()
    assert port_widget.items() == []


def test_port_mode_rejects_out_of_range(port_widget):
    port_widget._input.setText("99999")
    port_widget._add_from_input()
    assert port_widget.items() == []


def test_port_mode_accepts_valid(port_widget):
    port_widget._input.setText("8080")
    port_widget._add_from_input()
    assert port_widget.items() == ["8080"]


def test_remove_selected(widget):
    widget.setItems(["a", "b", "c"])
    widget._list.setCurrentRow(1)
    widget._remove_selected()
    assert widget.items() == ["a", "c"]


def test_textchanged_emitted(widget):
    got: list[int] = []
    widget.textChanged.connect(lambda: got.append(1))
    widget._input.setText("x")
    widget._add_from_input()
    assert got, "textChanged не сработал"
