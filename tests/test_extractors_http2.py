"""HTTP2Extractor: h2c и h2 из-под TLS по SSLKEYLOGFILE."""
from pathlib import Path

from hpack import Encoder

from paradox.config import Config
from paradox.extractors.http2 import HTTP2Extractor
from paradox.http2_parse import HTTP2_PREFACE
from paradox.models import CaptureState, FlowKey
from tests._tls_session import make_tls_session


def frame(
    frame_type: int,
    flags: int,
    stream_id: int,
    payload: bytes = b"",
) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def _request_bytes(path: str, body: bytes = b"") -> bytes:
    encoder = Encoder()
    block = encoder.encode([
        (b":method", b"POST"),
        (b":path", path.encode()),
        (b":authority", b"c2.example"),
        (b"content-type", b"application/octet-stream"),
    ])
    return (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, 0x4, 1, block)
        + frame(0, 0x1, 1, body)
    )


def _response_bytes(path: str, body: bytes = b"ok") -> bytes:
    encoder = Encoder()
    block = encoder.encode([
        (b":status", b"200"),
        (b"content-type", b"text/plain"),
    ])
    return (
        frame(4, 0, 0)
        + frame(1, 0x4, 1, block)
        + frame(0, 0x1, 1, body)
    )


def _pair(client: bytes, server: bytes, port: int = 8080) -> CaptureState:
    state = CaptureState()
    state.tcp_streams[
        FlowKey("tcp", "10.0.0.5", "10.0.0.10", 49152, port)
    ] = client
    state.tcp_streams[
        FlowKey("tcp", "10.0.0.10", "10.0.0.5", port, 49152)
    ] = server
    return state


def test_h2c_request_and_response_are_paired():
    state = _pair(
        _request_bytes("/upload", b"\x00\x01binary"),
        _response_bytes("/upload"),
    )

    HTTP2Extractor().run_post_extract(state, Config())

    assert state.h2_connections == 1
    assert state.h2_streams == 1
    assert state.tls_decrypted_streams == 0

    objects = [(key, obj) for key, obj in state.http_objects]
    requests = [(k, o) for k, o in objects if o.kind == "request"]
    responses = [(k, o) for k, o in objects if o.kind == "response"]
    assert len(requests) == 1 and len(responses) == 1

    _, request = requests[0]
    assert (request.method, request.uri, request.version) == (
        "POST", "/upload", "2",
    )
    assert request.headers["host"] == "c2.example"
    assert request.body == b"\x00\x01binary"

    response_key, response = responses[0]
    assert response.status_code == 200
    assert response.uri == "/upload"
    assert response_key.dst_port == 49152


def test_tls_h2_is_decrypted_with_keylog(tmp_path: Path):
    session = make_tls_session(
        tmp_path,
        tls13=True,
        client_payload=_request_bytes("/beacon", b"\xde\xad\xbe\xef"),
        server_payload=_response_bytes("/beacon"),
    )
    state = _pair(session.client_raw, session.server_raw, port=443)

    HTTP2Extractor().run_post_extract(
        state, Config(tls_keylog_path=str(session.keylog_path)),
    )

    assert state.tls_decrypted_streams == 1
    assert state.tls_decrypted_records > 0
    assert state.h2_connections == 1
    requests = [o for _, o in state.http_objects if o.kind == "request"]
    assert requests and requests[0].uri == "/beacon"
    assert requests[0].body == b"\xde\xad\xbe\xef"


def test_tls_h2_without_keylog_stays_closed(tmp_path: Path):
    session = make_tls_session(
        tmp_path,
        tls13=True,
        client_payload=_request_bytes("/x"),
        server_payload=_response_bytes("/x"),
    )
    state = _pair(session.client_raw, session.server_raw, port=443)

    HTTP2Extractor().run_post_extract(state, Config())

    assert state.http_objects == []
    assert state.tls_streams_without_keylog == 1
    assert state.h2_connections == 0


def test_tls_http1_is_decrypted_into_objects(tmp_path: Path):
    session = make_tls_session(tmp_path, tls13=True)
    state = _pair(session.client_raw, session.server_raw, port=443)

    HTTP2Extractor().run_post_extract(
        state, Config(tls_keylog_path=str(session.keylog_path)),
    )

    assert state.tls_http1_objects == 2
    assert state.h2_connections == 0
    requests = [o for _, o in state.http_objects if o.kind == "request"]
    responses = [o for _, o in state.http_objects if o.kind == "response"]
    assert requests[0].method == "GET"
    assert requests[0].uri == "/"
    assert responses[0].status_code == 200
    assert responses[0].uri == "/"


def test_http1_streams_are_ignored():
    state = _pair(
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        port=80,
    )

    HTTP2Extractor().run_post_extract(state, Config())

    assert state.http_objects == []
    assert state.h2_connections == 0


def test_h2_objects_feed_existing_detectors():
    from paradox.detectors.encoded_payload import EncodedPayloadDetector

    encoder = Encoder()
    block = encoder.encode([
        (b":method", b"GET"),
        (
            b":path",
            b"/x?site=aHR0cHM6Ly9taW5maW4uc2FtcmVnaW9uLnJ1",
        ),
        (b":authority", b"interface.fabi.me"),
    ])
    client = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, 0x4 | 0x1, 1, block)
    )
    state = _pair(client, _response_bytes("/x"), port=443)

    HTTP2Extractor().run_post_extract(state, Config())
    findings = EncodedPayloadDetector().run(state, Config())

    assert [f.type for f in findings] == ["encoded_payload"]
    assert "minfin.samregion.ru" in findings[0].value


def test_http2_disabled():
    state = _pair(_request_bytes("/x"), _response_bytes("/x"))

    HTTP2Extractor().run_post_extract(state, Config(http2_enabled=False))

    assert state.http_objects == []
