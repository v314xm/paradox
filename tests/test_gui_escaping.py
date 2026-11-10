"""GUI: данные отчёта экранируются перед setHtml (не исполняются)."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def test_timeline_details_escape_report_data(qapp):
    from paradox_gui.views.timeline_view import TimelineView

    view = TimelineView()
    view.update_data({"timeline": [{
        "ts": 1.0,
        "kind": "finding",
        "type": "xss<test>",
        "phase": "<b>exec</b>",
        "confidence": 0.9,
        "mitre_id": "<i>T1</i>",
        "confidence_reasons": ["<script>alert(1)</script>"],
        "evidence": {"k<script>": "<img src=x onerror=1>"},
        "description": "<script>alert('x')</script>",
    }]})

    item = view.tree.topLevelItem(0).child(0)
    view._on_item_clicked(item, 0)

    html = view.details.toHtml()
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_host_story_escapes_report_data(qapp):
    from PySide6.QtWidgets import QTextBrowser

    from paradox_gui.dialogs.host_story_dialog import HostStoryDialog

    dialog = HostStoryDialog("10.0.0.5", {
        "target_ip": "10.0.0.5<img src=x onerror=1>",
        "summary": {"total_events": 1, "findings_count": 1, "flows_count": 0},
        "events": [{
            "type": "finding",
            "ts": 1.0,
            "data": {"type": "t<script>", "value": "<b>x</b>"},
        }],
    })

    html = dialog.findChild(QTextBrowser).toHtml()
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_graph_node_double_click_skips_subnets(qapp):
    """Подсеть — не хост: диалог истории для неё не открывается."""
    from unittest.mock import MagicMock

    from PySide6.QtWidgets import QGraphicsSceneMouseEvent

    from paradox_gui.dialogs.graph_dialog import InteractiveNode

    dialog = MagicMock()
    node = InteractiveNode(0, 0, 10, "10.0.0.0/24", [], 0, dialog)

    node.mouseDoubleClickEvent(QGraphicsSceneMouseEvent())

    dialog.open_host_story.assert_not_called()
