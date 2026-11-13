"""Язык ядра: паритет каталогов и английский отчёт.

Русский каталог — источник истины: английский обязан покрывать те же
типы и правила, сохранять все подстановки `{key}` и не содержать
кириллицы. Иначе в отчёте появится английский текст с русской дырой
внутри или, хуже, потеряется значение находки.
"""
from __future__ import annotations

import re

import pytest

from paradox.explain.catalog import FINDING_SPECS
from paradox.explain.catalog_en import FINDING_SPECS_EN
from paradox.explain.contradiction_catalog import RULE_SPECS
from paradox.explain.contradiction_catalog_en import RULE_SPECS_EN
from paradox.i18n import (
    DEFAULT_LANGUAGE,
    get_language,
    is_english,
    reset_language,
    set_language,
)
from paradox.reporters.markdown.document import render_markdown

PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
CYRILLIC = re.compile("[А-Яа-яЁё]")


@pytest.fixture(autouse=True)
def _default_language():
    reset_language()
    yield
    reset_language()


def _texts(spec) -> list[str]:
    return [
        spec.headline,
        spec.why,
        *spec.next_steps,
        *spec.alternatives,
        spec.beginner,
    ]


@pytest.mark.parametrize(
    ("ru_catalog", "en_catalog"),
    [(FINDING_SPECS, FINDING_SPECS_EN), (RULE_SPECS, RULE_SPECS_EN)],
)
def test_english_catalog_covers_every_key(ru_catalog, en_catalog):
    assert set(en_catalog) == set(ru_catalog)


@pytest.mark.parametrize(
    ("ru_catalog", "en_catalog"),
    [(FINDING_SPECS, FINDING_SPECS_EN), (RULE_SPECS, RULE_SPECS_EN)],
)
def test_english_catalog_keeps_placeholders(ru_catalog, en_catalog):
    for key, ru_spec in ru_catalog.items():
        ru_placeholders = {p for text in _texts(ru_spec)
                           for p in PLACEHOLDER.findall(text)}
        en_spec = en_catalog[key]
        en_placeholders = {p for text in _texts(en_spec)
                           for p in PLACEHOLDER.findall(text)}
        assert en_placeholders == ru_placeholders, key


@pytest.mark.parametrize(
    ("ru_catalog", "en_catalog"),
    [(FINDING_SPECS, FINDING_SPECS_EN), (RULE_SPECS, RULE_SPECS_EN)],
)
def test_english_catalog_keeps_structure(ru_catalog, en_catalog):
    for key, ru_spec in ru_catalog.items():
        en_spec = en_catalog[key]
        assert len(en_spec.next_steps) == len(ru_spec.next_steps), key
        assert len(en_spec.alternatives) == len(ru_spec.alternatives), key


@pytest.mark.parametrize(
    ("ru_catalog", "en_catalog"),
    [(FINDING_SPECS, FINDING_SPECS_EN), (RULE_SPECS, RULE_SPECS_EN)],
)
def test_english_catalog_has_no_cyrillic(ru_catalog, en_catalog):
    for key, spec in en_catalog.items():
        for text in _texts(spec):
            assert not CYRILLIC.search(text), (key, text)


def _empty_report() -> dict:
    return {
        "provenance": {
            "pcap_path": "demo.pcap",
            "tool_version": "1.8.0",
            "pcap_sha256": "0" * 64,
        },
        "summary": {"packets": 1},
        "findings": [],
        "flows": {},
        "entities": {},
        "http": {},
        "contradictions": [],
    }


def test_report_is_russian_by_default():
    markdown = render_markdown(_empty_report())
    assert "## Сводка" in markdown
    assert "## Summary" not in markdown
    assert get_language() == DEFAULT_LANGUAGE


def test_report_switches_to_english():
    set_language("en")
    markdown = render_markdown(_empty_report())
    assert "## Summary" in markdown
    assert "**Tool:**" in markdown
    assert "Сводка" not in markdown
    assert not CYRILLIC.search(markdown)
    assert is_english()


def test_html_report_switches_to_english():
    from paradox.reporters.html_reporter import render_html

    set_language("en")
    markup = render_html(_empty_report())
    assert '<html lang="en">' in markup
    assert "Summary" in markup
    assert "Сводка" not in markup
    assert "Противоречий" not in markup


def test_html_report_is_russian_by_default():
    from paradox.reporters.html_reporter import render_html

    markup = render_html(_empty_report())
    assert '<html lang="ru">' in markup
    assert "Сводка" in markup


def test_confidence_reasons_follow_language():
    from paradox.detectors.explainer import build_reasons

    evidence = {"flow_count": 2, "bytes_sent": 54}
    assert build_reasons(evidence) == [
        "Количество потоков: 2",
        "Байт отправлено: 54",
    ]
    set_language("en")
    assert build_reasons(evidence) == ["Flows: 2", "Bytes sent: 54"]


def test_unknown_language_keeps_previous():
    set_language("en")
    with pytest.warns(UserWarning):
        set_language("de")
    assert get_language() == "en"


def test_cli_lang_detection():
    from paradox.cli import _lang_from_argv

    assert _lang_from_argv([]) == "ru"
    assert _lang_from_argv(["--lang", "en", "a.pcap"]) == "en"
    assert _lang_from_argv(["--lang=en"]) == "en"
    assert _lang_from_argv(["--lang"]) == "ru"
