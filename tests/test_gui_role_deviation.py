"""GUI: узел графа с ролью role_deviation раскрашивается как опасный."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402


@pytest.fixture
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def test_role_deviation_node_is_danger(qapp):
    from PySide6.QtGui import QColor

    from paradox_gui.dialogs.graph_dialog import InteractiveNode
    from paradox_gui.theme import PALETTE

    node = InteractiveNode(
        0, 0, 10, "10.0.0.5", ["internal", "role_deviation"], 0, None,
    )
    assert node.default_brush.color().name() == QColor(PALETTE["danger"]).name()


def test_normal_internal_node_is_not_danger(qapp):
    from PySide6.QtGui import QColor

    from paradox_gui.dialogs.graph_dialog import InteractiveNode
    from paradox_gui.theme import PALETTE

    node = InteractiveNode(
        0, 0, 10, "10.0.0.5", ["internal"], 0, None,
    )
    assert node.default_brush.color().name() != QColor(PALETTE["danger"]).name()
