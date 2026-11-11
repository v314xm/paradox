"""HTTP/2 framing и HPACK: заголовки, DATA, мультиплексирование."""
from hpack import Encoder

from paradox.http2_parse import (
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_PADDED,
    FLAG_PRIORITY,
    HTTP2_PREFACE,
    parse_http2_stream,
)


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


def test_parses_request_with_body():
    encoder = Encoder()
    header_block = encoder.encode([
        (b":method", b"POST"),
        (b":path", b"/upload"),
        (b":authority", b"evil.example"),
        (b"content-type", b"application/octet-stream"),
    ])
    stream = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, FLAG_END_HEADERS, 1, header_block)
        + frame(0, FLAG_END_STREAM, 1, b"\x00\x01\x02")
    )

    result = parse_http2_stream(stream)

    assert result.is_http2
    assert result.frames == 3
    assert result.streams == 1
    message = result.messages[0]
    assert (message.kind, message.method, message.uri) == (
        "request", "POST", "/upload",
    )
    assert message.headers["host"] == "evil.example"
    assert message.body == b"\x00\x01\x02"
    assert message.body_size == 3


def test_parses_response_without_preface():
    encoder = Encoder()
    block = encoder.encode([
        (b":status", b"200"),
        (b"content-type", b"text/plain"),
    ])
    stream = (
        frame(4, 0, 0)
        + frame(1, FLAG_END_HEADERS, 1, block)
        + frame(0, FLAG_END_STREAM, 1, b"ok")
    )

    result = parse_http2_stream(stream)

    assert result.is_http2
    message = result.messages[0]
    assert (message.kind, message.status_code) == ("response", 200)
    assert message.body == b"ok"


def test_headers_split_across_continuation():
    encoder = Encoder()
    block = encoder.encode([
        (b":method", b"GET"),
        (b":path", b"/" + b"a" * 40),
        (b":authority", b"example.test"),
    ])
    cut = len(block) // 2
    stream = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, FLAG_END_STREAM, 3, block[:cut])
        + frame(9, FLAG_END_HEADERS, 3, block[cut:])
    )

    result = parse_http2_stream(stream)

    message = result.messages[0]
    assert message.uri == "/" + "a" * 40
    assert message.headers["host"] == "example.test"


def test_padded_headers_with_priority():
    encoder = Encoder()
    block = encoder.encode([(b":method", b"GET"), (b":path", b"/p")])
    payload = (
        b"\x02"            # pad length
        + b"\x00\x00\x00\x00\x10"   # priority: dep + weight
        + block
        + b"\x00\x00"
    )
    stream = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(
            1, FLAG_END_HEADERS | FLAG_END_STREAM | FLAG_PADDED | FLAG_PRIORITY,
            1, payload,
        )
    )

    result = parse_http2_stream(stream)

    assert result.messages[0].uri == "/p"


def test_multiplexed_streams_share_hpack_table():
    encoder = Encoder()
    first = encoder.encode([
        (b":method", b"GET"),
        (b":path", b"/one"),
        (b":authority", b"example.test"),
    ])
    second = encoder.encode([
        (b":method", b"GET"),
        (b":path", b"/two"),
        (b":authority", b"example.test"),
    ])
    stream = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 1, first)
        + frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 3, second)
    )

    result = parse_http2_stream(stream)

    assert [m.uri for m in result.messages] == ["/one", "/two"]
    assert [m.stream_id for m in result.messages] == [1, 3]


def test_body_limit_truncates():
    encoder = Encoder()
    block = encoder.encode([(b":method", b"POST"), (b":path", b"/x")])
    stream = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, FLAG_END_HEADERS, 1, block)
        + frame(0, FLAG_END_STREAM, 1, b"0123456789")
    )

    message = parse_http2_stream(stream, body_limit=4).messages[0]

    assert message.body == b"0123"
    assert message.body_size == 10
    assert message.truncated


def test_padded_data_is_stripped():
    encoder = Encoder()
    block = encoder.encode([(b":method", b"POST"), (b":path", b"/x")])
    stream = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, FLAG_END_HEADERS, 1, block)
        + frame(0, FLAG_END_STREAM | FLAG_PADDED, 1, b"\x02ab\x00\x00")
    )

    assert parse_http2_stream(stream).messages[0].body == b"ab"


def test_non_http2_stream_is_ignored():
    result = parse_http2_stream(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")

    assert not result.is_http2
    assert result.messages == []


def test_max_messages_caps_streams():
    encoder = Encoder()
    first = encoder.encode([(b":method", b"GET"), (b":path", b"/a")])
    second = encoder.encode([(b":method", b"GET"), (b":path", b"/b")])
    stream = (
        HTTP2_PREFACE
        + frame(4, 0, 0)
        + frame(1, FLAG_END_HEADERS, 1, first)
        + frame(1, FLAG_END_HEADERS, 3, second)
    )

    assert len(parse_http2_stream(stream, max_messages=1).messages) == 1
