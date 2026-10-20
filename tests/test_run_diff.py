"""Тесты diff_reports (B1)."""
from paradox_gui.analyzers.run_diff import _finding_key, diff_reports


def _f(type_, value, **kw):
    return {"type": type_, "value": value, **kw}


def _c(rule, subject, **kw):
    return {"rule": rule, "subject": subject, **kw}


def test_empty_reports():
    d = diff_reports({}, {})
    assert d.findings.total == 0
    assert not d.has_changes()


def test_identical_reports_no_changes():
    r = {"findings": [_f("dga", "x.com")], "contradictions": []}
    d = diff_reports(r, r)
    assert d.findings.total == 0
    assert not d.has_changes()


def test_added_finding():
    old = {"findings": [_f("dga", "a.com")]}
    new = {"findings": [_f("dga", "a.com"), _f("beaconing", "1.2.3.4")]}
    d = diff_reports(old, new)
    assert len(d.findings.added) == 1
    assert d.findings.added[0]["type"] == "beaconing"
    assert d.has_changes()


def test_removed_finding():
    old = {"findings": [_f("dga", "a.com"), _f("beaconing", "1.2.3.4")]}
    new = {"findings": [_f("dga", "a.com")]}
    d = diff_reports(old, new)
    assert len(d.findings.removed) == 1
    assert d.findings.removed[0]["type"] == "beaconing"


def test_changed_confidence():
    old = {"findings": [_f("dga", "a.com", confidence=0.5)]}
    new = {"findings": [_f("dga", "a.com", confidence=0.9)]}
    d = diff_reports(old, new)
    assert len(d.findings.changed) == 1
    assert d.findings.changed[0]["changes"]["confidence"] == (0.5, 0.9)
    assert len(d.findings.added) == 0
    assert len(d.findings.removed) == 0


def test_changed_severity():
    old = {"findings": [_f("x", "y", severity="low")]}
    new = {"findings": [_f("x", "y", severity="high")]}
    d = diff_reports(old, new)
    assert len(d.findings.changed) == 1


def test_unchanged_findings():
    r = {"findings": [_f("dga", "a.com", confidence=0.5)]}
    d = diff_reports(r, r)
    assert len(d.findings.unchanged) == 1
    assert d.findings.total == 0


def test_contradictions_added_removed():
    old = {"findings": [], "contradictions": [_c("mac_ip_conflict", "10.0.0.1")]}
    new = {"findings": [], "contradictions": [_c("victim_makes_attack", "10.0.0.2")]}
    d = diff_reports(old, new)
    assert len(d.contradictions_added) == 1
    assert len(d.contradictions_removed) == 1


def test_summary_changes():
    old = {"findings": [], "summary": {"packets": 100, "flows": 10}}
    new = {"findings": [], "summary": {"packets": 150, "flows": 10}}
    d = diff_reports(old, new)
    assert "packets" in d.summary_changes
    assert d.summary_changes["packets"] == (100, 150)
    assert "flows" not in d.summary_changes


def test_finding_key_stable():
    assert _finding_key({"type": "a", "value": "b"}) == ("a", "b")
    assert _finding_key({}) == ("", "")
