"""
Тесты WebShellMarkersDetector.

Полезная нагрузка хранится в base64 и декодируется в рантайме:
в исходнике теста нет ни одной цельной сигнатуры шелла, иначе
антивирус на рабочей машине блокирует чтение файла (проверено
на Windows Defender). Содержимое констант — обычные тестовые
строки для проверки детектора.
"""
import base64
import gzip

from paradox.config import Config
from paradox.detectors.webshell_markers import WebShellMarkersDetector
from paradox.http_object import HttpObject
from paradox.models import CaptureState, FlowKey


def _payload(encoded: str) -> bytes:
    return base64.b64decode(encoded)


# PHP-шелл, ASP-шелл, JSP-шелл, маркер известного семейства.
_PHP_SHELL = _payload("PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=")
_CHOPPER = _payload(
    "PCVAIFBhZ2UgTGFuZ3VhZ2U9IkpzY3JpcHQiJT48JWV2YWwoUmVxdWVzdC5JdGVt"
    "WyJ6Il0sInVuc2FmZSIpOyU+"
)
_JSP = _payload(
    "PCUgUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhyZXF1ZXN0LmdldFBhcmFtZXRl"
    "cigiY21kIikpOyAlPg=="
)
_FAMILY_MARKER = _payload("JGF1dGhfcGFzcyA9ICd4JzsgJHdzb192ZXJzaW9uID0gJzIuNSc7")


def _state(objects):
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


def _response(body, uri="/x.php", ctype="text/plain", status=200):
    return {
        "kind": "response", "uri": uri, "status_code": status,
        "headers": {"content-type": ctype}, "body": body,
    }


def _request(body, uri="/upload.php", ctype="multipart/form-data"):
    return {
        "kind": "request", "method": "POST", "uri": uri,
        "headers": {"host": "victim.local", "content-type": ctype},
        "body": body, "dst_ip": "192.168.1.50",
    }


def test_php_eval_download():
    findings = WebShellMarkersDetector().run(
        _state([_response(_PHP_SHELL)]), Config(),
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "webshell_signature"
    assert f.severity == "critical"
    assert f.evidence["family"] == "php_eval"
    assert f.evidence["direction"] == "download"


def test_china_chopper_detected():
    findings = WebShellMarkersDetector().run(
        _state([_response(_CHOPPER, ctype="application/octet-stream")]),
        Config(),
    )
    assert len(findings) == 1
    assert findings[0].evidence["family"] == "china_chopper"


def test_jsp_runtime_exec_detected():
    findings = WebShellMarkersDetector().run(
        _state([_response(_JSP, ctype="application/octet-stream")]),
        Config(),
    )
    assert len(findings) == 1
    assert findings[0].evidence["family"] == "jsp_runtime"


def test_known_family_has_higher_confidence():
    findings = WebShellMarkersDetector().run(
        _state([_response(_FAMILY_MARKER, ctype="application/octet-stream")]),
        Config(),
    )
    assert findings[0].evidence["family"] == "wso"
    assert findings[0].confidence == 0.9


def test_webshell_upload_detected():
    body = (
        b"--x\r\nContent-Disposition: form-data; name=f\r\n\r\n"
        + _PHP_SHELL + b"\r\n--x--\r\n"
    )
    findings = WebShellMarkersDetector().run(
        _state([_request(body)]), Config(),
    )
    assert len(findings) == 1
    assert findings[0].evidence["direction"] == "upload"


def test_plain_eval_in_javascript_not_flagged():
    body = b"function f(x){ return eval(x); } console.log('system')"
    findings = WebShellMarkersDetector().run(
        _state([_response(body, ctype="application/javascript")]),
        Config(),
    )
    assert findings == []


def test_html_article_with_code_sample_not_flagged():
    body = b"<html><pre>" + _PHP_SHELL + b"</pre></html>"
    findings = WebShellMarkersDetector().run(
        _state([_response(body, ctype="text/html")]),
        Config(),
    )
    assert findings == []


def test_random_binary_not_flagged():
    body = bytes(range(256)) * 8
    findings = WebShellMarkersDetector().run(
        _state([_response(body, ctype="application/octet-stream")]),
        Config(),
    )
    assert findings == []


def test_gzip_response_decoded_and_matched():
    spec = _response(gzip.compress(_PHP_SHELL))
    spec["headers"]["content-encoding"] = "gzip"
    findings = WebShellMarkersDetector().run(_state([spec]), Config())
    assert len(findings) == 1


def test_same_uri_aggregated():
    findings = WebShellMarkersDetector().run(
        _state([_response(_PHP_SHELL), _response(_PHP_SHELL)]), Config(),
    )
    assert len(findings) == 1
    assert findings[0].evidence["count"] == 2


def test_download_and_upload_are_separate():
    findings = WebShellMarkersDetector().run(
        _state([_response(_PHP_SHELL), _request(_PHP_SHELL)]), Config(),
    )
    directions = {f.evidence["direction"] for f in findings}
    assert directions == {"download", "upload"}


def test_empty_state():
    assert WebShellMarkersDetector().run(CaptureState(), Config()) == []


def test_payload_sample_is_kept_for_viewer():
    from paradox.payload_excerpt import decode_sample

    findings = WebShellMarkersDetector().run(
        _state([_response(_PHP_SHELL)]), Config(),
    )

    sample = findings[0].evidence["payload_samples"][0]
    assert sample["direction"] == "response"
    assert decode_sample(sample) == _PHP_SHELL
