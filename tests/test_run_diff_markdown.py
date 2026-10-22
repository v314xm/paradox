"""Тесты render_diff_markdown (fix_34).

Покрывает строки 110-202 paradox_gui/analyzers/run_diff.py —
функцию рендера Markdown-отчёта о различиях. diff_reports()
уже покрыт test_run_diff.py, здесь только рендер.
"""
from paradox_gui.analyzers.run_diff import (
    diff_reports,
    render_diff_markdown,
)


def _report(findings=None, contradictions=None, summary=None,
            pcap="a.pcap"):
    return {
        "provenance": {"pcap_path": pcap},
        "findings": findings or [],
        "contradictions": contradictions or [],
        "summary": summary or {},
    }


# ================== пустой diff ==================

def test_empty_diff_says_no_changes():
    d = diff_reports(_report(), _report())
    md = render_diff_markdown(d)
    assert "Изменений нет" in md


# ================== header ==================

def test_header_contains_both_filenames():
    old = _report(pcap="old.pcap", findings=[])
    new = _report(pcap="new.pcap", findings=[
        {"type": "dga_domain", "value": "evil.com", "confidence": 0.8},
    ])
    md = render_diff_markdown(diff_reports(old, new))
    assert "old.pcap" in md
    assert "new.pcap" in md
    assert "Diff:" in md


def test_header_counts_findings():
    old = _report(findings=[])
    new = _report(findings=[
        {"type": "dga_domain", "value": "evil.com", "confidence": 0.8},
    ])
    md = render_diff_markdown(diff_reports(old, new))
    assert "+1" in md  # added


# ================== findings added / removed / changed ==================

def test_added_findings_section():
    old = _report(findings=[])
    new = _report(findings=[
        {"type": "dga_domain", "value": "evil.com", "confidence": 0.8},
    ])
    md = render_diff_markdown(diff_reports(old, new))
    assert "## Новые findings" in md
    assert "evil.com" in md
    assert "dga_domain" in md
    assert "0.80" in md  # confidence формат


def test_removed_findings_section():
    old = _report(findings=[
        {"type": "dga_domain", "value": "gone.com", "confidence": 0.7},
    ])
    new = _report(findings=[])
    md = render_diff_markdown(diff_reports(old, new))
    assert "## Исчезли findings" in md
    assert "gone.com" in md


def test_changed_findings_section():
    old = _report(findings=[
        {"type": "dga_domain", "value": "x.com", "confidence": 0.5},
    ])
    new = _report(findings=[
        {"type": "dga_domain", "value": "x.com", "confidence": 0.9},
    ])
    md = render_diff_markdown(diff_reports(old, new))
    assert "## Изменились findings" in md
    assert "x.com" in md
    # changes_str = "confidence: 0.5→0.9"
    assert "confidence" in md
    assert "0.5" in md
    assert "0.9" in md


# ================== contradictions ==================

def test_contradictions_added_section():
    old = _report(contradictions=[])
    new = _report(contradictions=[{
        "rule": "sni_host_mismatch",
        "subject": "1.1.1.1",
        "severity": "high",
        "confidence": 0.7,
    }])
    md = render_diff_markdown(diff_reports(old, new))
    assert "## Новые противоречия" in md
    assert "sni_host_mismatch" in md
    assert "1.1.1.1" in md
    assert "high" in md


def test_contradictions_removed_section():
    old = _report(contradictions=[{
        "rule": "victim_makes_attack",
        "subject": "2.2.2.2",
        "severity": "critical",
        "confidence": 0.9,
    }])
    new = _report(contradictions=[])
    md = render_diff_markdown(diff_reports(old, new))
    assert "## Исчезли противоречия" in md
    assert "victim_makes_attack" in md
    assert "2.2.2.2" in md


def test_header_counts_contradictions():
    old = _report(contradictions=[])
    new = _report(contradictions=[{
        "rule": "x", "subject": "1.1.1.1", "severity": "high",
    }])
    md = render_diff_markdown(diff_reports(old, new))
    assert "**Противоречия:**" in md
    assert "+1" in md


# ================== summary changes ==================

def test_summary_section_positive_delta():
    old = _report(summary={"packets": 100})
    new = _report(summary={"packets": 250})
    md = render_diff_markdown(diff_reports(old, new))
    assert "## Изменения в сводке" in md
    assert "packets" in md
    assert "100" in md
    assert "250" in md
    assert "+150" in md


def test_summary_section_negative_delta():
    old = _report(summary={"packets": 500})
    new = _report(summary={"packets": 100})
    md = render_diff_markdown(diff_reports(old, new))
    assert "-400" in md


def test_summary_table_header():
    old = _report(summary={"packets": 100})
    new = _report(summary={"packets": 200})
    md = render_diff_markdown(diff_reports(old, new))
    assert "| Поле | Было | Стало | Дельта |" in md


# ================== всё вместе ==================

def test_all_sections_together():
    old = _report(
        pcap="old.pcap",
        findings=[
            {"type": "dga_domain", "value": "removed.com", "confidence": 0.7},
            {"type": "dga_domain", "value": "changed.com", "confidence": 0.5},
        ],
        contradictions=[
            {"rule": "old_rule", "subject": "1.1.1.1", "severity": "low"},
        ],
        summary={"packets": 100},
    )
    new = _report(
        pcap="new.pcap",
        findings=[
            {"type": "dga_domain", "value": "changed.com", "confidence": 0.9},
            {"type": "dga_domain", "value": "added.com", "confidence": 0.8},
        ],
        contradictions=[
            {"rule": "new_rule", "subject": "2.2.2.2", "severity": "high"},
        ],
        summary={"packets": 200},
    )
    md = render_diff_markdown(diff_reports(old, new))

    # все секции присутствуют
    assert "## Изменения в сводке" in md
    assert "## Новые findings" in md
    assert "## Исчезли findings" in md
    assert "## Изменились findings" in md
    assert "## Новые противоречия" in md
    assert "## Исчезли противоречия" in md

    # все значения попали
    for needle in ("removed.com", "changed.com", "added.com",
                   "old_rule", "new_rule", "packets"):
        assert needle in md


# ================== защита от None/пустого ==================

def test_render_does_not_crash_on_missing_provenance():
    old = {"findings": []}
    new = {"findings": [
        {"type": "dga_domain", "value": "x.com", "confidence": 0.8},
    ]}
    md = render_diff_markdown(diff_reports(old, new))
    # Path("").name → "", заголовок содержит "?" или пустую строку
    # главное — не упало
    assert isinstance(md, str)
    assert "## Новые findings" in md


def test_render_does_not_crash_on_missing_confidence():
    old = _report(findings=[])
    new = _report(findings=[
        {"type": "dga_domain", "value": "x.com"},  # нет confidence
    ])
    md = render_diff_markdown(diff_reports(old, new))
    assert isinstance(md, str)
    assert "x.com" in md
