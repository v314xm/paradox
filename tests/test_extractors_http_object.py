"""Тесты HTTPObjectExtractor — сборка HTTP из TCP-потоков."""
from dataclasses import dataclass

from paradox.extractors.http_object import HTTPObjectExtractor
from paradox.models import CaptureState, FlowKey


@dataclass
class _FakeConfig:
    """Минимальный Config для экстрактора.

    НЕ используем MagicMock: getattr(MagicMock(), 'attr', default)
    возвращает MagicMock (не default), и http_object.py падает
    на `int > MagicMock`.
    """
    http_object_body_limit: int = 1024 * 1024


def _key(src, dst, sport, dport):
    return FlowKey("tcp", src, dst, sport, dport)


def test_http_object_request_and_response_paired():
    """Парный request+response: у response есть URI из request."""
    state = CaptureState()
    client_key = _key("10.0.0.5", "1.1.1.1", 54321, 80)
    server_key = _key("1.1.1.1", "10.0.0.5", 80, 54321)

    state.tcp_streams[client_key] = (
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        b"User-Agent: curl/8.0\r\n\r\n"
    )
    state.tcp_streams[server_key] = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        b"Content-Length: 5\r\n\r\nHELLO"
    )

    HTTPObjectExtractor().run_post_extract(state, config=_FakeConfig())

    assert len(state.http_objects) == 2
    kinds = [obj.kind for _, obj in state.http_objects]
    assert "request" in kinds
    assert "response" in kinds

    # response получил URI из парного request
    for k, obj in state.http_objects:
        if obj.kind == "response":
            assert obj.uri == "/index.html"
            assert obj.body == b"HELLO"
            assert obj.status_code == 200


def test_http_object_only_request():
    """Только request (без response) — один объект."""
    state = CaptureState()
    key = _key("10.0.0.5", "1.1.1.1", 54321, 80)
    state.tcp_streams[key] = b"POST /api HTTP/1.1\r\nHost: x.com\r\n\r\n"
    HTTPObjectExtractor().run_post_extract(state, config=_FakeConfig())

    assert len(state.http_objects) == 1
    _, obj = state.http_objects[0]
    assert obj.kind == "request"
    assert obj.method == "POST"
    assert obj.uri == "/api"


def test_http_object_non_http_stream_ignored():
    """Не-HTTP поток (TLS handshake) — пропускается."""
    state = CaptureState()
    key = _key("10.0.0.5", "1.1.1.1", 54321, 443)
    state.tcp_streams[key] = b"\x16\x03\x01\x00\x50 FAKE_TLS"
    HTTPObjectExtractor().run_post_extract(state, config=_FakeConfig())
    assert state.http_objects == []


def test_http_object_empty_streams_noop():
    """Пустой state — ничего не происходит."""
    state = CaptureState()
    HTTPObjectExtractor().run_post_extract(state, config=_FakeConfig())
    assert state.http_objects == []
