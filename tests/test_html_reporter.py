"""
Тесты HTML-отчёта: структура, экранирование, сортировка, IOC.
"""
from paradox.reporters.html_reporter import render_html, write_html


def _finding(**overrides):
    base = {
        "type": "typosquatting",
        "value": "evil-c2.live",
        "severity": "low",
        "confidence": 0.6,
        "src_ip": "10.0.0.10",
        "dst_ip": "203.0.113.7",
        "dst_port": 443,
        "mitre_id": "T1583",
        "first_seen": 1700000000,
        "evidence": {"host": "evil-c2.live"},
    }
    base.update(overrides)
    return base


def _report(**overrides):
    base = {
        "provenance": {
            "tool_version": "1.4.0",
            "pcap_path": "capture.pcap",
            "pcap_sha256": "abc123",
        },
        "summary": {
            "packets": 1000,
            "flows": 42,
            "findings": 1,
            "contradictions": 0,
            "http_objects": 7,
            "unique_dns_queries": 5,
            "carved_files": 2,
            "uploaded_bytes": 2048,
            "protocols": {"by_l4": {"tcp": 40}, "by_l7": {"tls": 10}},
        },
        "findings": [_finding()],
        "contradictions": [],
        "timeline": [],
    }
    base.update(overrides)
    return base


def test_document_structure():
    doc = render_html(_report())
    assert doc.startswith("<!doctype html>")
    assert "</html>" in doc
    assert "<style>" in doc
    assert "capture.pcap" in doc
    assert "1.4.0" in doc
    assert "abc123" in doc


def test_summary_and_protocols():
    doc = render_html(_report())
    assert ">1000<" in doc
    assert "tcp: 40" in doc
    assert "tls: 10" in doc


def test_values_are_escaped():
    payload = "<script>alert(1)</script>"
    doc = render_html(_report(findings=[_finding(value=payload)]))
    assert payload not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc


def test_findings_sorted_by_severity():
    findings = [
        _finding(value="low-one", severity="low"),
        _finding(value="crit-one", severity="critical"),
    ]
    doc = render_html(_report(findings=findings))
    assert doc.index("crit-one") < doc.index("low-one")


def test_contradiction_rendered():
    contradiction = {
        "rule": "victim_makes_attack",
        "subject": "192.168.1.12",
        "severity": "critical",
        "confidence": 0.9,
        "priority": 0.9,
        "likely_causes": ["pivot"],
        "resolution_hint": "смотреть WinRM",
        "facts": [{
            "source": "finding", "subject": "192.168.1.12",
            "predicate": "attacker_of", "value": "192.168.1.1",
            "ts": 1700000000, "confidence": 0.8, "evidence": {},
        }],
    }
    doc = render_html(_report(contradictions=[contradiction]))
    assert "victim_makes_attack" in doc
    assert "pivot" in doc
    assert "смотреть WinRM" in doc
    assert "attacker_of" in doc


def test_timeline_rendered():
    event = {
        "ts": 1700000000, "phase": "execution", "severity": "high",
        "type": "webshell_upload", "description": "заливка шелла",
    }
    doc = render_html(_report(timeline=[event]))
    assert "webshell_upload" in doc
    assert "заливка шелла" in doc


def test_ioc_section_from_findings():
    doc = render_html(_report())
    assert "[domain-name:value = &#x27;evil-c2.live&#x27;]" in doc \
        or "domain-name" in doc
    assert "203.0.113.7" in doc


def test_empty_report_is_safe():
    doc = render_html({"findings": [], "contradictions": [], "timeline": []})
    assert "Findings не найдены" in doc
    assert "Противоречий не найдено" in doc
    assert "Таймлайн пуст" in doc


def test_deterministic_output():
    report = _report()
    assert render_html(report) == render_html(report)


def test_write_html(tmp_path):
    path = tmp_path / "report.html"
    written = write_html(_report(), path)
    assert written == path
    text = path.read_text(encoding="utf-8")
    assert "Paradox" in text
    assert "evil-c2.live" in text
