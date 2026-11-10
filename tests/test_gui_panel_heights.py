"""GUI: блоки «Противоречия» и «DNS без ответа» не обрезают содержимое."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def _contra(index: int) -> dict:
    return {
        "severity": "high",
        "rule": "SniWithoutDnsRule",
        "subject": f"cdn{index}.example.org",
        "confidence": 0.82,
        "resolution_hint": "TLS SNI без DNS-запроса к этому домену.",
        "facts": [
            {"source": "tls", "key": "sni", "value": "cdn.example.org"},
        ],
    }


def test_contradictions_section_fits_two_cards(qapp):
    from paradox_gui.widgets.contradictions_section import (
        ContradictionsSection,
    )

    section = ContradictionsSection()
    section.set_contradictions([_contra(1), _contra(2)])
    section.resize(1200, 600)
    section.show()
    qapp.processEvents()

    # Высота по содержимому: карточки не прячутся за внутренним скроллом.
    assert section._scroll.verticalScrollBar().maximum() == 0
    assert section.height() >= 2 * 80


def test_contradictions_section_scrolls_when_list_is_long(qapp):
    from paradox_gui.widgets.contradictions_section import (
        ContradictionsSection,
    )

    section = ContradictionsSection()
    section.set_contradictions([_contra(i) for i in range(8)])
    section.resize(1200, 600)
    section.show()
    qapp.processEvents()

    # Потолок держит список, чтобы он не выдавливал таблицу findings.
    assert section._scroll.verticalScrollBar().maximum() > 0
    assert section.height() < section._list_layout.sizeHint().height()


def test_absence_table_shows_several_rows(qapp):
    from paradox_gui.widgets.absence_panel import AbsencePanel

    panel = AbsencePanel()
    panel.update_report({
        "absence": {
            "dns_unanswered": [
                {"qname": f"host{i}.example.org", "count": i + 1}
                for i in range(12)
            ],
            "tcp_unanswered": [],
        },
    })
    panel.resize(1200, 600)
    panel.show()
    qapp.processEvents()

    table = panel.table_dns
    rows = (
        table.height() - table.horizontalHeader().height()
    ) // table.rowHeight(0)
    assert rows >= 7


def test_absence_clear_hides_panel_and_drops_rows(qapp):
    from paradox_gui.widgets.absence_panel import AbsencePanel

    panel = AbsencePanel()
    panel.update_report({
        "absence": {
            "dns_unanswered": [{"qname": "a.example", "count": 1}],
            "tcp_unanswered": [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                                "dst_port": 80, "packets": 1}],
        },
    })
    assert panel.isHidden() is False

    panel.clear()

    assert panel.isHidden() is True
    assert panel.table_dns.rowCount() == 0
    assert panel.table_tcp.rowCount() == 0
