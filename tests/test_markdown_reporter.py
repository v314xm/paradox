"""Тесты Markdown-репортера.

render_markdown(report) -> str. Проверяем:
  - заголовок с именем pcap;
  - summary-секцию;
  - findings / contradictions / carved_files / HTTP — по факту данных;
  - пустой отчёт не падает.
"""
from paradox.reporters.markdown_reporter import render_markdown


def _minimal_report(**extra) -> dict:
    """Минимальный валидный report для render_markdown."""
    base = {
        "provenance": {
            "tool_version": "1.0.0",
            "pcap_path": "test.pcap",
            "pcap_sha256": "a" * 64,
        },
        "summary": {
            "packets": 100,
            "flows": 10,
            "unique_dns_queries": 5,
            "nxdomain_count": 1,
            "findings": 0,
            "contradictions": 0,
            "extractor_errors": {},
        },
        "findings": [],
        "contradictions": [],
        "entities": {"internal": [], "external": []},
        "flows": {"top_by_bytes": []},
        "http": {},
        "carved_files": {"files": []},
        "absence": {},
        "ndp": {},
    }
    base.update(extra)
    return base


def test_render_markdown_empty():
    """Пустой отчёт: render не падает, есть заголовок."""
    md = render_markdown(_minimal_report())
    assert isinstance(md, str)
    assert md.startswith("# PCAP Triage Report")
    assert "test.pcap" in md
    assert "## Сводка" in md


def test_render_markdown_with_findings():
    """С findings — есть секция и хотя бы одна строка."""
    report = _minimal_report(findings=[{
        "type": "dga_domain",
        "value": "xj3k9q2.example",
        "confidence": 0.8,
        "severity": "medium",
        "src_ip": "10.0.0.5",
        "dst_ip": "8.8.8.8",
        "mitre_techniques": ["T1568.002"],
        "evidence": {},
    }])
    report["summary"]["findings"] = 1
    md = render_markdown(report)
    assert "dga_domain" in md
    assert "xj3k9q2.example" in md


def test_render_markdown_with_contradictions():
    """Есть contradictions — рисуется секция."""
    report = _minimal_report(contradictions=[{
        "rule": "victim_makes_attack",
        "subject": "10.0.0.42",
        "severity": "critical",
        "confidence": 0.9,
        "facts": [],
        "likely_causes": ["pivot"],
        "resolution_hint": "check pivot",
    }])
    report["summary"]["contradictions"] = 1
    md = render_markdown(report)
    assert "victim_makes_attack" in md
    assert "10.0.0.42" in md


def test_render_markdown_with_carved_files():
    """Есть carved_files — секция с sha256."""
    report = _minimal_report(carved_files={
        "files": [{
            "sha256": "b" * 64,
            "ext": ".exe",
            "size": 1024,
            "uri": "/dl/x.exe",
            "first_bytes_hex": "4d5a",
            "truncated": False,
            "saved_path": None,
        }],
        "total": 1,
    })
    md = render_markdown(report)
    assert "Carved Files" in md
    assert "bbbbbbbb" in md  # начало sha256
    assert "/dl/x.exe" in md


def test_render_markdown_with_http():
    """Есть HTTP-секция — top_hosts рисуются."""
    report = _minimal_report(http={
        "unique_hosts": 1,
        "unique_uris": 1,
        "unique_user_agents": 1,
        "methods": [{"method": "GET", "count": 3}],
        "top_hosts": [{"host": "example.com", "count": 3}],
        "top_uris": [{
            "method": "GET",
            "host": "example.com",
            "uri": "/index.html",
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "dst_port": 80,
            "bytes": 512,
            "user_agent": "curl/8.0",
        }],
        "top_user_agents": [{"user_agent": "curl/8.0", "count": 1}],
    })
    md = render_markdown(report)
    assert "## HTTP" in md
    assert "example.com" in md
    assert "/index.html" in md
