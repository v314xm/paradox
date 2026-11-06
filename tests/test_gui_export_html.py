"""
GUI: HTML-формат во вкладке «Экспорт».
"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _report():
    return {
        "provenance": {"tool_version": "1.4.0", "pcap_path": "x.pcap"},
        "summary": {"packets": 10, "flows": 2, "findings": 1},
        "findings": [{
            "type": "typosquatting",
            "value": "evil.live",
            "severity": "high",
            "confidence": 0.8,
            "src_ip": "10.0.0.1",
            "dst_ip": "203.0.113.9",
            "evidence": {},
        }],
        "contradictions": [],
        "timeline": [],
    }


def test_html_format_present_and_generates_document(qapp):
    from paradox_gui.views.export_view import ExportView

    view = ExportView()
    formats = [
        view.format_combo.itemData(i)
        for i in range(view.format_combo.count())
    ]
    assert "html" in formats

    view.update_data(_report())
    index = formats.index("html")
    view.format_combo.setCurrentIndex(index)

    assert view._current_export_data.startswith("<!doctype html>")
    assert "evil.live" in view._current_export_data


def test_csv_and_stix_still_work(qapp):
    from paradox_gui.views.export_view import ExportView

    view = ExportView()
    view.update_data(_report())
    formats = [
        view.format_combo.itemData(i)
        for i in range(view.format_combo.count())
    ]

    view.format_combo.setCurrentIndex(formats.index("csv"))
    assert view._current_export_data.startswith("Type,Value")

    view.format_combo.setCurrentIndex(formats.index("stix"))
    assert '"type": "bundle"' in view._current_export_data
