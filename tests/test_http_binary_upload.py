"""
Тесты HttpBinaryUploadDetector.

Сценарий: заражённый хост шлёт серию POST'ов с бинарным телом
(application/octet-stream) по случайным URI на внешний хост.
Легитимные OCSP-запросы и текстовые формы не должны попадать.
"""
from paradox.config import Config
from paradox.detectors.http_binary_upload import HttpBinaryUploadDetector
from paradox.http_object import HttpObject
from paradox.models import CaptureState, FlowKey

_BINARY = b"\x1f\x8b" + bytes(range(256)) * 8


def _state(requests, dst_ip="104.21.16.1", src_ip="10.6.13.133"):
    """
    requests: list of (uri, body, content_type, host).
    """
    state = CaptureState()
    objs = []
    for i, (uri, body, content_type, host) in enumerate(requests):
        key = FlowKey(
            proto="tcp", src_ip=src_ip, dst_ip=dst_ip,
            src_port=50000 + i, dst_port=80,
        )
        obj = HttpObject(
            kind="request",
            method="POST",
            uri=uri,
            headers={
                "host": host,
                "content-type": content_type,
            },
            body=body,
            body_size=len(body),
        )
        objs.append((key, obj))
    state.http_objects = objs
    return state


def test_binary_upload_series_detected():
    requests = [
        (f"/Rand{i}/x&{i}/y", _BINARY, "application/octet-stream",
         "evil-c2.live")
        for i in range(5)
    ]
    findings = HttpBinaryUploadDetector().run(_state(requests), Config())

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "http_binary_upload"
    assert f.evidence["host"] == "evil-c2.live"
    assert f.evidence["post_count"] == 5
    assert f.evidence["unique_uris"] == 5
    assert 0.55 <= f.confidence <= 0.75


def test_text_posts_not_flagged():
    body = b"user=admin&password=secret"
    requests = [
        ("/login", body, "application/x-www-form-urlencoded", "api.example.com")
        for _ in range(5)
    ]
    findings = HttpBinaryUploadDetector().run(_state(requests), Config())
    assert findings == []


def test_ocsp_posts_not_flagged():
    """OCSP — нормальный бинарный POST, не exfil."""
    requests = [
        ("/", _BINARY, "application/ocsp-request", "ocsp.digicert.com")
        for _ in range(5)
    ]
    findings = HttpBinaryUploadDetector().run(_state(requests), Config())
    assert findings == []


def test_single_post_not_flagged():
    requests = [("/upload", _BINARY, "application/octet-stream", "cdn.example")
                ]
    findings = HttpBinaryUploadDetector().run(_state(requests), Config())
    assert findings == []


def test_small_bodies_not_flagged():
    small = b"\x00\x01\x02"
    requests = [
        (f"/x{i}", small, "application/octet-stream", "evil.live")
        for i in range(5)
    ]
    findings = HttpBinaryUploadDetector().run(_state(requests), Config())
    assert findings == []


def test_inbound_upload_not_flagged():
    """Ответ внешнего сервера — это не наш POST."""
    state = _state([
        ("/x", _BINARY, "application/octet-stream", "evil.live"),
    ] * 5, dst_ip="10.6.13.133", src_ip="104.21.16.1")
    findings = HttpBinaryUploadDetector().run(state, Config())
    assert findings == []


def test_allowlist_suffix_skips_host():
    config = Config(
        http_binary_upload_allowlist_suffixes=frozenset({"example.com"}),
    )
    requests = [
        (f"/x{i}", _BINARY, "application/octet-stream", "updates.example.com")
        for i in range(5)
    ]
    findings = HttpBinaryUploadDetector().run(_state(requests), config)
    assert findings == []


def test_aggregates_per_host_not_per_uri():
    requests = [
        (f"/r{i}", _BINARY, "application/octet-stream", "evil.live")
        for i in range(4)
    ]
    findings = HttpBinaryUploadDetector().run(_state(requests), Config())
    assert len(findings) == 1
    assert findings[0].evidence["post_count"] == 4


def test_empty_state():
    assert HttpBinaryUploadDetector().run(CaptureState(), Config()) == []
