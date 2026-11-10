"""Тесты EncodedPayloadDetector: base64/hex URL в query и теле формы."""
import base64

from paradox.config import Config
from paradox.detectors.encoded_payload import EncodedPayloadDetector
from paradox.http_object import HttpObject
from paradox.models import CaptureState, FlowKey

B64_SITE = base64.b64encode(
    b"https://minfin.samregion.ru",
).decode()


def _state(*objects: HttpObject) -> CaptureState:
    state = CaptureState()
    key = FlowKey(
        proto="tcp", src_ip="10.100.18.7", dst_ip="85.13.164.70",
        src_port=57176, dst_port=80,
    )
    state.http_objects = [(key, obj) for obj in objects]
    return state


def _request(
    uri: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    truncated: bool = False,
) -> HttpObject:
    return HttpObject(
        kind="request", method="POST", uri=uri,
        headers=headers or {"host": "interface.fabi.me"},
        body=body,
        truncated=truncated,
    )


def test_base64_url_in_query_detected():
    state = _state(_request(
        "/wpfilebase-pro/stats-sink.php?"
        f"pl_slug=wp-filebase&site={B64_SITE}&nocache=1",
    ))

    findings = EncodedPayloadDetector().run(state, Config())

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "encoded_payload"
    assert f.src_ip == "10.100.18.7"
    assert f.dst_ip == "85.13.164.70"
    assert f.value == "site=https://minfin.samregion.ru"
    assert f.evidence["encoding"] == "base64"
    assert f.evidence["decoded"] == "https://minfin.samregion.ru"
    assert f.evidence["param"] == "site"
    assert f.evidence["uri_path"] == "/wpfilebase-pro/stats-sink.php"
    assert f.evidence["in_body"] is False


def test_hex_url_detected():
    value = b"https://c2.example/gate".hex()
    state = _state(_request(f"/go?next={value}"))

    findings = EncodedPayloadDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].evidence["encoding"] == "hex"
    assert findings[0].evidence["decoded"] == "https://c2.example/gate"


def test_base64_url_in_form_body_detected():
    body = f"next={B64_SITE}".encode()
    state = _state(_request(
        "/go",
        headers={
            "host": "interface.fabi.me",
            "content-type": "application/x-www-form-urlencoded",
        },
        body=body,
    ))

    findings = EncodedPayloadDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].evidence["in_body"] is True
    assert findings[0].evidence["decoded"] == "https://minfin.samregion.ru"


def test_plain_text_base64_ignored():
    value = base64.b64encode(b"hello world, not a url").decode()
    state = _state(_request(f"/go?note={value}"))

    assert EncodedPayloadDetector().run(state, Config()) == []


def test_random_binary_token_ignored():
    value = base64.b64encode(bytes(range(48))).decode()
    state = _state(_request(f"/go?token={value}"))

    assert EncodedPayloadDetector().run(state, Config()) == []


def test_short_value_ignored():
    value = base64.b64encode(b"https:").decode()
    state = _state(_request(f"/go?next={value}"))

    assert EncodedPayloadDetector().run(state, Config()) == []


def test_response_body_ignored():
    response = HttpObject(
        kind="response", status_code=200,
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=f"next={B64_SITE}".encode(),
    )
    state = _state(response)

    assert EncodedPayloadDetector().run(state, Config()) == []


def test_truncated_body_ignored():
    state = _state(_request(
        "/go",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=f"next={B64_SITE}".encode(),
        truncated=True,
    ))

    assert EncodedPayloadDetector().run(state, Config()) == []


def test_non_form_body_ignored():
    state = _state(_request(
        "/go",
        headers={"content-type": "application/json"},
        body=f'{{"next": "{B64_SITE}"}}'.encode(),
    ))

    assert EncodedPayloadDetector().run(state, Config()) == []


def test_same_param_is_reported_once():
    state = _state(_request(f"/go?next={B64_SITE}&next={B64_SITE}"))

    findings = EncodedPayloadDetector().run(state, Config())

    assert len(findings) == 1
