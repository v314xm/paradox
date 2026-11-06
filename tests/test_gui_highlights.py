"""GUI: панель «Что привлекло внимание» — карточки хайлайтов."""
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
        "http": {
            "top_uris": [
                {
                    "method": "POST",
                    "uri": "/upload",
                    "host": "evil.example",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "203.0.113.9",
                    "dst_port": 443,
                    "bytes": 2048,
                },
                {
                    "method": "GET",
                    "uri": "/a",
                    "host": "example.com",
                    "bytes": 1024,
                },
                {
                    "method": "GET",
                    "uri": "/b",
                    "host": "example.org",
                    "bytes": 512,
                },
            ],
        },
        "flows": {
            "top_by_bytes": [
                {
                    "src_ip": "10.0.0.5",
                    "dst_ip": "203.0.113.9",
                    "dst_port": 443,
                    "direction": "out",
                    "bytes": 12 * 1024 * 1024,
                },
                {
                    "src_ip": "10.0.0.6",
                    "dst_ip": "198.51.100.7",
                    "dst_port": 80,
                    "direction": "in",
                    "bytes": 4096,
                },
            ],
        },
        "entities": {
            "external": [
                {"ip": "203.0.113.9", "roles": ["c2", "resolver"]},
                {"ip": "198.51.100.7", "roles": []},
            ],
        },
    }


def test_cards_built_and_capped(qapp):
    from paradox_gui.widgets.highlights_panel import _MAX_CARDS, HighlightsPanel

    panel = HighlightsPanel()
    panel.update_report(_report())

    cards = panel.cards()
    assert len(cards) == _MAX_CARDS == 6
    assert [c.kind() for c in cards] == [
        "http", "http", "http", "flow", "flow", "ext",
    ]
    assert cards[0].primary_text() == "POST /upload"
    assert cards[0].secondary_text() == "evil.example"
    assert cards[0].metric_text() == "2.0 KB"
    assert cards[3].primary_text() == "10.0.0.5 → 203.0.113.9:443"
    assert cards[3].metric_text() == "12.0 MB"
    assert cards[5].primary_text() == "203.0.113.9"


def test_empty_report_shows_empty_state(qapp):
    from paradox_gui.i18n import tr
    from paradox_gui.widgets.highlights_panel import HighlightsPanel

    panel = HighlightsPanel()
    panel.update_report({"http": {}, "flows": {}, "entities": {}})

    assert panel.cards() == []
    assert panel._empty.isVisible() is False  # ещё не показан на экране
    assert panel._empty.text() == tr("high.empty")
    assert all(chip.isHidden() for chip in panel._chips.values())


def test_filter_chips_show_only_matching_cards(qapp):
    from paradox_gui.widgets.highlights_panel import HighlightsPanel

    panel = HighlightsPanel()
    panel.update_report(_report())

    assert [c.kind() for c in panel.cards()] == [
        "http", "http", "http", "flow", "flow", "ext",
    ]
    assert panel._count.text() == "6"
    assert not panel._chips["ext"].isHidden()

    panel._chips["ext"].click()
    assert [c.kind() for c in panel.cards()] == ["ext", "ext"]
    assert panel._count.text() == "2 / 7"
    assert panel._chips["ext"].isChecked()

    panel._chips[None].click()
    assert len(panel.cards()) == 6
    assert panel._count.text() == "6"


def test_first_card_fades_in(qapp):
    from PySide6.QtWidgets import QGraphicsOpacityEffect

    from paradox_gui.widgets.highlights_panel import HighlightsPanel

    panel = HighlightsPanel()
    panel.update_report(_report())
    assert isinstance(
        panel.cards()[0].graphicsEffect(), QGraphicsOpacityEffect
    )

    # Переключение фильтра не должно анимировать заново — иначе
    # чипы будут «мигать» при каждом клике.
    panel._chips["ext"].click()
    assert all(c.graphicsEffect() is None for c in panel.cards())


def test_values_are_plain_text_not_html(qapp):
    from paradox_gui.widgets.highlights_panel import HighlightsPanel

    report = _report()
    report["http"]["top_uris"][0]["host"] = "<img src=x onerror=alert(1)>"

    panel = HighlightsPanel()
    panel.update_report(report)

    card = panel.cards()[0]
    assert card.secondary_text() == "<img src=x onerror=alert(1)>"
    assert "&lt;img" in card.toolTip()


def test_repeated_update_replaces_cards(qapp):
    from paradox_gui.widgets.highlights_panel import HighlightsPanel

    panel = HighlightsPanel()
    panel.update_report(_report())
    panel.update_report({"http": {}, "flows": {}, "entities": {}})

    assert panel.cards() == []
    assert panel._count.isVisible() is False


def test_theme_defines_highlight_card_styles():
    from paradox_gui.theme import QSS

    assert "QFrame#highlightCard" in QSS
    assert 'QFrame#highlightCard[kind="flow"]' in QSS
    assert "QLabel#highlightBadge" in QSS
