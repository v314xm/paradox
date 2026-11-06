"""
Тесты PhpPayloadDetector.

Маркер `<?php` в теле отличает скачанный PHP-скрипт от обычной
страницы. Расширение `.php` не используется сознательно:
/index.php и /wp-login.php есть в любом захвате.
"""
from paradox.config import Config
from paradox.detectors.php_payload import PhpPayloadDetector
from paradox.http_object import HttpObject
from paradox.models import CaptureState, FlowKey

_PHP = b"<?php system($_GET['c']); ?>"
_HTML_WITH_CODE = (
    b"<html><body><pre>&lt;?php echo 1; ?&gt;</pre></body></html>"
)


def _state(objects):
    """
    objects: list of dict(kind, method, uri, status_code, headers, body).
    Flow: клиент 10.0.0.10 <-> сервер 203.0.113.7:80.
    """
    state = CaptureState()
    pairs = []
    for i, spec in enumerate(objects):
        body = spec.get("body", b"")
        obj = HttpObject(
            kind=spec["kind"],
            method=spec.get("method"),
            uri=spec.get("uri"),
            status_code=spec.get("status_code"),
            headers=spec.get("headers", {}),
            body=body,
            body_size=len(body),
        )
        if spec["kind"] == "request":
            key = FlowKey(
                proto="tcp", src_ip=spec.get("src_ip", "10.0.0.10"),
                dst_ip=spec.get("dst_ip", "203.0.113.7"),
                src_port=40000 + i, dst_port=80,
            )
        else:
            key = FlowKey(
                proto="tcp", src_ip="203.0.113.7", dst_ip="10.0.0.10",
                src_port=80, dst_port=40000 + i,
            )
        pairs.append((key, obj))
    state.http_objects = pairs
    return state


def _response(body, uri="/uploads/x.php", status=200, ctype="application/octet-stream"):
    return {
        "kind": "response", "uri": uri, "status_code": status,
        "headers": {"content-type": ctype}, "body": body,
    }


def test_php_download_detected():
    findings = PhpPayloadDetector().run(
        _state([_response(_PHP)]), Config(),
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "php_download"
    assert f.severity == "high"
    assert f.confidence == 0.85
    assert f.evidence["marker"] == "<?php"
    assert f.evidence["kind"] == "download"


def test_html_page_with_code_sample_not_flagged():
    findings = PhpPayloadDetector().run(
        _state([_response(_HTML_WITH_CODE, ctype="text/html")]), Config(),
    )
    assert findings == []


def test_php_body_not_at_start_not_flagged_for_response():
    """Маркер в середине ответа — не исходник, а данные."""
    body = b"<html>" + b"x" * 200 + _PHP
    findings = PhpPayloadDetector().run(
        _state([_response(body, ctype="text/plain")]), Config(),
    )
    assert findings == []


def test_webshell_upload_detected():
    spec = {
        "kind": "request", "method": "POST", "uri": "/upload.php",
        "headers": {
            "host": "victim.local",
            "content-type": "multipart/form-data; boundary=x",
        },
        "body": b"--x\r\nContent-Disposition: form-data; name=f\r\n\r\n"
                + _PHP + b"\r\n--x--\r\n",
        "dst_ip": "192.168.1.50",
    }
    findings = PhpPayloadDetector().run(_state([spec]), Config())
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "webshell_upload"
    assert f.severity == "critical"
    assert f.confidence == 0.85
    assert f.evidence["host"] == "victim.local"


def test_get_with_php_body_not_flagged():
    """GET с телом — не заливка шелла."""
    spec = {
        "kind": "request", "method": "GET", "uri": "/x.php",
        "headers": {"host": "victim.local"}, "body": _PHP,
    }
    findings = PhpPayloadDetector().run(_state([spec]), Config())
    assert findings == []


def test_error_response_not_flagged():
    findings = PhpPayloadDetector().run(
        _state([_response(_PHP, status=404)]), Config(),
    )
    assert findings == []


def test_gzip_response_with_php_detected():
    """Сжатый PHP-исходник распаковывается и находится."""
    import gzip

    spec = _response(gzip.compress(_PHP))
    spec["headers"]["content-encoding"] = "gzip"
    findings = PhpPayloadDetector().run(_state([spec]), Config())
    assert len(findings) == 1
    assert findings[0].type == "php_download"


def test_gzip_binary_response_not_flagged():
    spec = _response(b"\x1f\x8b" + b"\x00" * 100)
    spec["headers"]["content-encoding"] = "gzip"
    findings = PhpPayloadDetector().run(_state([spec]), Config())
    assert findings == []


def test_same_uri_aggregated():
    findings = PhpPayloadDetector().run(
        _state([_response(_PHP), _response(_PHP)]), Config(),
    )
    assert len(findings) == 1
    assert findings[0].evidence["count"] == 2


def test_download_and_upload_are_separate_findings():
    response = _response(_PHP)
    request = {
        "kind": "request", "method": "POST", "uri": "/upload.php",
        "headers": {"host": "victim.local", "content-type": "text/plain"},
        "body": _PHP, "dst_ip": "192.168.1.50",
    }
    findings = PhpPayloadDetector().run(
        _state([response, request]), Config(),
    )
    assert {f.type for f in findings} == {"php_download", "webshell_upload"}


def test_empty_state():
    assert PhpPayloadDetector().run(CaptureState(), Config()) == []
