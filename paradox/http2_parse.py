"""HTTP/2 framing и HPACK → объекты запросов/ответов.

HTTP/2 — бинарный протокол: 9-байтный заголовок кадра, заголовки
сжаты HPACK и могут занимать несколько кадров HEADERS/CONTINUATION,
тела идут кадрами DATA. Соединение мультиплексируется: в одном
направлении TCP параллельно живут десятки stream id.

Что разбираем: HEADERS (+CONTINUATION, padding, priority) и DATA,
псевдозаголовки `:method`, `:path`, `:authority`, `:status`.
PUSH_PROMISE раскодируем только чтобы не сломать динамическую
таблицу HPACK. SETTINGS/PING/WINDOW_UPDATE/RST_STREAM/GOAWAY
пропускаются. Приоритеты и flow control не моделируются.

HPACK (включая таблицу Хаффмана) берётся из пакета `hpack`: это
единственный практичный способ не ошибиться в RFC 7541 Appendix B.

Текстовый HTTP/1 сюда не попадает: без префейса первый кадр должен
быть валидным SETTINGS на stream 0, иначе поток не считается h2.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hpack import Decoder

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DEFAULT_BODY_LIMIT = 1 * 1024 * 1024

FRAME_DATA = 0
FRAME_HEADERS = 1
FRAME_PRIORITY = 2
FRAME_RST_STREAM = 3
FRAME_SETTINGS = 4
FRAME_PUSH_PROMISE = 5
FRAME_PING = 6
FRAME_GOAWAY = 7
FRAME_WINDOW_UPDATE = 8
FRAME_CONTINUATION = 9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

_MAX_FRAME_LEN = 16 * 1024 * 1024


@dataclass
class Http2Message:
    stream_id: int
    kind: str                     # "request" | "response"
    method: str | None = None
    uri: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_size: int = 0
    truncated: bool = False


@dataclass
class Http2Result:
    is_http2: bool = False
    messages: list[Http2Message] = field(default_factory=list)
    frames: int = 0
    streams: int = 0
    errors: int = 0


def _strip_padding(payload: bytes, flags: int) -> bytes:
    if flags & FLAG_PADDED:
        if not payload:
            return b""
        pad = payload[0]
        payload = payload[1:]
        if pad and pad <= len(payload):
            payload = payload[:-pad]
        elif pad:
            return b""
    return payload


def _strip_priority(payload: bytes, flags: int) -> bytes:
    if flags & FLAG_PRIORITY:
        return payload[5:]
    return payload


def parse_http2_stream(
    stream: bytes,
    body_limit: int = DEFAULT_BODY_LIMIT,
    max_messages: int = 200,
) -> Http2Result:
    result = Http2Result()
    if not stream:
        return result

    pos = 0
    if stream.startswith(HTTP2_PREFACE):
        pos = len(HTTP2_PREFACE)

    decoder = Decoder()
    messages: dict[int, Http2Message] = {}
    order: list[int] = []
    block = bytearray()
    block_kind: str | None = None   # "headers" | "promise"
    block_stream = 0
    checked_first = False

    def finish_block() -> None:
        nonlocal block, block_kind
        if block_kind is None:
            block = bytearray()
            return
        if block_kind == "promise":
            # Заголовки обещанного потока нужны только для HPACK.
            try:
                decoder.decode(bytes(block))
            except Exception:
                result.errors += 1
            block = bytearray()
            block_kind = None
            return
        finalize_headers(block_stream)
        block = bytearray()
        block_kind = None

    def finalize_headers(stream_id: int) -> None:
        if not block:
            return
        try:
            headers = decoder.decode(bytes(block))
        except Exception:
            result.errors += 1
            return

        kind: str | None = None
        method: str | None = None
        uri: str | None = None
        status_code: int | None = None
        regular: dict[str, str] = {}
        for name, value in headers:
            if name == ":method":
                kind = "request"
                method = value
            elif name == ":path":
                uri = value
            elif name == ":status":
                kind = "response"
                try:
                    status_code = int(value)
                except ValueError:
                    status_code = None
            elif name == ":authority":
                regular["host"] = value
            elif name.startswith(":"):
                continue
            else:
                regular[name] = value

        if kind is None or stream_id in messages:
            # trailer'ы или повторный блок — HPACK уже раскодирован
            return
        messages[stream_id] = Http2Message(
            stream_id=stream_id,
            kind=kind,
            method=method,
            uri=uri,
            status_code=status_code,
            headers=regular,
        )
        order.append(stream_id)
        result.streams += 1

    while pos + 9 <= len(stream) and len(order) < max_messages:
        length = int.from_bytes(stream[pos:pos + 3], "big")
        if length > _MAX_FRAME_LEN:
            result.errors += 1
            break
        if pos + 9 + length > len(stream):
            result.errors += 1
            break
        frame_type = stream[pos + 3]
        flags = stream[pos + 4]
        stream_id = int.from_bytes(stream[pos + 5:pos + 9], "big") & 0x7FFFFFFF
        payload = stream[pos + 9:pos + 9 + length]
        pos += 9 + length
        result.frames += 1

        if not checked_first:
            checked_first = True
            is_settings = (
                frame_type == FRAME_SETTINGS
                and stream_id == 0
                and (
                    (flags & FLAG_ACK and length == 0)
                    or (not flags & FLAG_ACK and length % 6 == 0)
                )
            )
            if not is_settings:
                return result
            result.is_http2 = True

        if frame_type == FRAME_SETTINGS:
            continue

        if frame_type == FRAME_HEADERS:
            fragment = _strip_padding(payload, flags)
            fragment = _strip_priority(fragment, flags)
            block = bytearray(fragment)
            block_kind = "headers"
            block_stream = stream_id
            if flags & FLAG_END_HEADERS:
                finish_block()
            continue

        if frame_type == FRAME_PUSH_PROMISE:
            fragment = _strip_padding(payload, flags)
            fragment = fragment[4:] if len(fragment) >= 4 else b""
            block = bytearray(fragment)
            block_kind = "promise"
            block_stream = stream_id
            if flags & FLAG_END_HEADERS:
                finish_block()
            continue

        if frame_type == FRAME_CONTINUATION:
            if block_kind is None:
                continue
            block.extend(payload)
            if flags & FLAG_END_HEADERS:
                finish_block()
            continue

        if frame_type == FRAME_DATA:
            message = messages.get(stream_id)
            if message is None:
                continue
            data = _strip_padding(payload, flags)
            message.body_size += len(data)
            room = body_limit - len(message.body)
            if room > 0:
                message.body += data[:room]
            if len(data) > max(room, 0):
                message.truncated = True
            continue

    result.messages = [messages[sid] for sid in order]
    return result
