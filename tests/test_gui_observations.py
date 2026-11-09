"""GUI: панель «Что видел инструмент» — цветовые маркеры категорий."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


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
    )
    assert all(row._value.text() == "—" for row in rows)
    assert all(row._value.property("empty") is True for row in rows)
