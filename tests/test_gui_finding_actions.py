"""GUI: правая колонка действий у находок и переходы в инструменты."""
import base64
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _payload_sample() -> dict:
    # Тело намеренно без сигнатур шеллов: Defender блокирует чтение
    # файлов с цельными строками вроде eval($_POST…).
    body = b"<html><body>upload ok</body></html>"
    return {
        "direction": "request",
        "method": "POST",
        "host": "reabilit.samregion.ru",
        "uri": "/uploads/file.php",
        "content_type": "application/octet-stream",
        "size": len(body),
        "truncated": False,
        "is_text": True,
        "sha256": "a" * 64,
        "text_b64": base64.b64encode(body).decode("ascii"),
    }


def _report() -> dict:
    return {
        "summary": {"findings": 3, "contradictions": 0},
        "contradictions": [],
        "findings": [
            {
                "type": "webshell_upload",
                "value": "185.10.10.5 → reabilit.samregion.ru",
                "confidence": 0.95,
                "src_ip": "185.10.10.5",
                "dst_ip": "10.0.0.5",
                "evidence": {
                    "src_ip": "185.10.10.5",
                    "dst_ip": "10.0.0.5",
                    "payload_samples": [_payload_sample()],
                },
            },
            {
                "type": "dga_domain",
                "value": "evil.example",
                "confidence": 0.60,
                "evidence": {},
            },
            {
                "type": "tls_fingerprint",
                "value": "ja3:deadbeef",
                "confidence": 0.40,
                "evidence": {},
            },
        ],
    }


def _row_of(table, finding_type: str) -> int:
    for row in range(table._table.rowCount()):
        item = table._table.item(row, 0)
        if item is not None and item.text() == finding_type:
            return row
    raise AssertionError(f"row not found: {finding_type}")


def test_table_selection_drives_panel(qapp):
    from paradox_gui.widgets.finding_actions import FindingActionsPanel
    from paradox_gui.widgets.findings_table import FindingsTable

    report = _report()
    table = FindingsTable()
    panel = FindingActionsPanel()
    table.selection_changed.connect(panel.set_finding)

    table.set_findings(report["findings"])
    selected = table.selected_finding()
    assert selected is not None, "первая видимая строка должна быть выбрана"
    assert panel.btn_details.isEnabled()

    table._table.selectRow(_row_of(table, "dga_domain"))
    selected = table.selected_finding()
    assert selected["type"] == "dga_domain"
    assert panel.btn_enrich.isEnabled()
    assert not panel.btn_payload.isEnabled(), "у находки нет выдержки тела"
    assert not panel.btn_host.isEnabled(), "в evidence нет IP хоста"


def test_panel_report_flags_and_filter_chip(qapp):
    from paradox_gui.widgets.finding_actions import FindingActionsPanel

    panel = FindingActionsPanel()
    panel.set_report_flags(
        has_report=True, has_attack_graph=True, has_files=False,
    )
    assert panel.btn_graph.isEnabled()
    assert panel.btn_attack_graph.isEnabled()
    assert not panel.btn_files.isEnabled()

    panel.set_filter_active(True)
    assert panel.btn_reset_filter.isVisibleTo(panel)

    panel.clear()
    assert not panel.btn_graph.isEnabled()
    assert not panel.btn_reset_filter.isVisibleTo(panel)


def test_payload_view_selects_finding_excerpt(qapp):
    from paradox_gui.views.payload_view import PayloadView

    report = _report()
    view = PayloadView()
    view.update_data(report)

    assert view.select_finding(report["findings"][0]) == 0
    assert view._list.currentRow() == 0
    assert view.select_finding(report["findings"][1]) == -1


def test_enrich_view_marks_finding_iocs(qapp):
    from paradox_gui.views.enrich_view import EnrichView

    report = _report()
    view = EnrichView()
    view.set_report(report)

    count = view.focus_finding(report["findings"][0])
    assert count == 1
    row = view._cand_table.currentRow()
    assert view._cand_table.item(row, 1).text() == "185.10.10.5"

    assert view.focus_finding(report["findings"][2]) == 0


def test_run_view_panel_button_emits_selected_finding(qapp):
    from paradox_gui.views.run_view import RunView

    view = RunView()
    view.load_report(_report())

    seen: list[dict] = []
    view.payload_requested.connect(seen.append)
    view.finding_actions.btn_payload.click()
    assert seen and seen[0]["type"] == "webshell_upload"

    copied: list[str] = []
    view.finding_actions.copy_requested.connect(copied.append)
    view.finding_actions.btn_copy.click()
    assert copied == ["185.10.10.5 → reabilit.samregion.ru"]


def test_main_window_jumps_into_payload_and_enrich(qapp):
    from paradox_gui.main_window import MainWindow

    report = _report()
    window = MainWindow()
    try:
        window.run_view.load_report(report)
        window.enrich_view.set_report(report)

        window._on_finding_payload(report["findings"][0])
        assert window.tabs.currentWidget() is window.payload_view
        assert window.payload_view._list.currentRow() == 0

        window._on_finding_enrich(report["findings"][0])
        assert window.tabs.currentWidget() is window.enrich_view
        assert window.enrich_view._cand_table.currentRow() >= 0
    finally:
        window.close()
