"""GUI: панель «Что видел инструмент» — цветовые маркеры категорий."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_rows_have_kind_dots(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    kinds = [
        row._dot.property("kind")
        for row in (
            panel._row_http, panel._row_dns, panel._row_flows,
            panel._row_hosts, panel._row_tcp, panel._row_carved,
        )
    ]
    assert kinds == ["http", "dns", "flow", "hosts", "tcp", "carved"]


def test_missing_values_are_muted(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    panel.update_report({
        "summary": {"flows": 0, "unique_dns_queries": 0,
                    "nxdomain_count": 0, "carved_files": 0},
        "http": {},
        "entities": {},
    })

    assert panel._row_dns._value.property("empty") is True
    assert panel._row_tcp._value.property("empty") is True
    assert panel._row_carved._value.property("empty") is True
    # Нулевые счётчики — тоже пустое состояние, а не метрика.
    assert panel._row_http._value.property("empty") is True
    assert panel._row_flows._value.property("empty") is True
    assert panel._row_hosts._value.property("empty") is True


def test_real_values_are_not_muted(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    panel.update_report({
        "summary": {"flows": 5, "unique_dns_queries": 3,
                    "nxdomain_count": 1, "tcp_streams": 2,
                    "carved_files": 1},
        "http": {"unique_hosts": 1, "unique_uris": 2,
                 "methods": [{"method": "GET"}], "unique_user_agents": 1},
        "entities": {"internal": [{"ip": "10.0.0.1"}],
                     "external": [{"ip": "203.0.113.9"}]},
    })

    assert panel._row_http._value.property("empty") is False
    assert panel._row_dns._value.property("empty") is False
    assert panel._row_flows._value.property("empty") is False
    assert panel._row_carved._value.property("empty") is False


def test_clear_resets_to_dash(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    panel.update_report({
        "summary": {"flows": 5, "unique_dns_queries": 3,
                    "nxdomain_count": 1, "tcp_streams": 2,
                    "carved_files": 1},
        "http": {"unique_hosts": 1, "unique_uris": 2,
                 "methods": [{"method": "GET"}], "unique_user_agents": 1},
        "entities": {"internal": [{"ip": "10.0.0.1"}], "external": []},
    })

    panel.clear()

    rows = (
        panel._row_http, panel._row_dns, panel._row_flows,
        panel._row_hosts, panel._row_tcp, panel._row_carved,
        panel._row_traffic, panel._row_protocols, panel._row_tls,
        panel._row_diag,
    )
    assert all(row._value.text() == "—" for row in rows)
    assert all(row._value.property("empty") is True for row in rows)


def test_traffic_protocols_tls_and_parsing_rows(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    panel.update_report({
        "summary": {
            "flows": 1234,
            "tcp_streams": 300,
            "uploaded_bytes": 4 * 1024 * 1024,
            "downloaded_bytes": 18 * 1024 * 1024,
            "certificates": 4,
            "tls_decrypted_streams": 12,
            "extractor_errors": {"http": 2},
            "smb2_parse_errors": 1,
            "tls_streams_without_keylog": 5,
            "tcp_streams_truncated": 7,
            "protocols": {"by_l7": {
                "http": 120, "tls": 80, "dns": 40, "smb": 10, "ssh": 3,
            }},
        },
        "http": {},
        "entities": {},
    })

    traffic = panel._row_traffic._value.text()
    assert "↑ 4.0 МБ" in traffic
    assert "↓ 18.0 МБ" in traffic
    assert panel._row_traffic._value.property("empty") is False

    protocols = panel._row_protocols._value.text()
    assert protocols.startswith("HTTP 120 · TLS 80 · DNS 40 · SMB 10")
    assert protocols.endswith("+1"), "хвост протоколов свернуть в +N"

    assert "сертификатов: 4" in panel._row_tls._value.text()

    diag = panel._row_diag._value.text()
    assert "ошибок разбора: 3" in diag
    assert "TLS без ключей: 5" in diag
    assert "обрезано: 7" in diag


def test_new_rows_are_muted_without_data(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    panel.update_report({"summary": {}, "http": {}, "entities": {}})

    for row in (
        panel._row_traffic, panel._row_protocols,
        panel._row_tls, panel._row_diag,
    ):
        assert row._value.text() == "—"
        assert row._value.property("empty") is True


def test_kpi_tiles_show_verdict(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    panel.update_report({
        "summary": {
            "flows": 5,
            "certificates": 4,
            "tls_decrypted_streams": 31,
        },
        "findings": [
            {"type": "a", "severity": "high"},
            {"type": "b", "severity": "high"},
            {"type": "c", "severity": "medium"},
        ],
        "contradictions": [
            {"severity": "high"},
            {"severity": "medium"},
        ],
        "carved_files": {
            "total": 3,
            "files": [{"ext": "php"}, {"ext": "php"}, {"ext": "exe"}],
        },
        "http": {},
        "entities": {},
    })

    assert panel._kpi_findings.value.text() == "3"
    assert "выс 2" in panel._kpi_findings.sub.text()
    assert "сред 1" in panel._kpi_findings.sub.text()

    assert panel._kpi_contra.value.text() == "2"
    assert panel._kpi_contra.value.property("hasContra") is True
    assert "выс 1" in panel._kpi_contra.sub.text()

    assert panel._kpi_files.value.text() == "3"
    assert "php 2" in panel._kpi_files.sub.text()

    assert panel._kpi_tls.value.text() == "4"
    assert "31" in panel._kpi_tls.sub.text()


def test_kpi_tiles_muted_without_data(qapp):
    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    panel.update_report({"summary": {}, "http": {}, "entities": {}})

    for tile in (
        panel._kpi_findings, panel._kpi_contra,
        panel._kpi_files, panel._kpi_tls,
    ):
        # Ноль — это факт вердикта («находок нет»), но показывается
        # приглушённо, как отсутствие метрики.
        assert tile.value.text() == "0"
        assert tile.value.property("empty") is True

    panel.clear()
    assert panel._kpi_findings.value.text() == "—"


def test_kpi_tiles_click_to_details(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QSignalSpy, QTest

    from paradox_gui.widgets.observations_panel import ObservationsPanel

    panel = ObservationsPanel()
    pairs = (
        (panel._kpi_findings, panel.findings_requested),
        (panel._kpi_contra, panel.contradictions_requested),
        (panel._kpi_files, panel.files_requested),
        (panel._kpi_tls, panel.certificates_requested),
    )
    for tile, signal in pairs:
        spy = QSignalSpy(signal)
        QTest.mouseClick(tile, Qt.MouseButton.LeftButton)
        assert spy.count() == 1


def test_run_view_status_line_has_capture_context(qapp):
    from paradox_gui.views.run_view import RunView

    view = RunView()
    view.load_report({
        "summary": {
            "packets": 1234,
            "size_bytes": 2048,
            "findings": 3,
            "contradictions": 1,
        },
        "findings": [],
        "contradictions": [],
    })

    text = view.status_label.text()
    assert "1 234" in text
    assert "2 КБ" in text
    assert "находок: 3" in text
    assert "противоречий: 1" in text
