"""
Парсер HTTP-объектов (запросы и ответы) из потока байт.

Работает поверх склеенного TCP-потока (state.tcp_streams). Отличается
от http_parse.py (тот читает первый сегмент) тем, что:
- видит заголовки полностью, даже если они пришли в 2-3 сегментах;
- читает body по Content-Length (до лимита);
- поддерживает Transfer-Encoding: chunked.

Не парсит:
- HTTP/2 (это не текст, а бинарный формат — другая история);
- multipart bodies (границы не разбираем, но body сохраняем как есть);
- gzip/deflate Content-Encoding (не распаковываем).

Что возвращает:
    HttpObject(
        kind="request" | "response",
        method=str | None,
        uri=str | None,
        version=str | None,
        status_code=int | None,
        headers=dict[str, str],
        body=bytes,
        body_size=int,
        truncated=bool,
    )

Или None, если в потоке не HTTP.
"""
from dataclasses import dataclass, field

from paradox.http_parse import HTTP_METHODS

# Максимум, сколько body читать (защита от гигабайтных ответов)
DEFAULT_BODY_LIMIT = 1 * 1024 * 1024


@dataclass
class HttpObject:
    kind: str                      # "request" | "response"
    method: str | None = None
    uri: str | None = None
    version: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_size: int = 0             # реальный размер из заголовка (или len(body))
    truncated: bool = False        # body обрезано лимитом
    consumed: int = 0              # сколько байт потока занимает сообщение


def parse_http_request(
    stream: bytes,
    body_limit: int = DEFAULT_BODY_LIMIT,
) -> HttpObject | None:
    """Разобрать HTTP-запрос из потока (или None, если это не запрос)."""
    if not stream:
        return None

    head_end = stream.find(b"\r\n\r\n")
    if head_end < 0:
        # Заголовки не найдены — не HTTP или фрагмент
        return None

    header_block = stream[:head_end]
    try:
        header_text = header_block.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None

    lines = header_text.split("\r\n")
    if not lines:
        return None

    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) != 3:
        return None
    method, uri, version = parts
    if method not in HTTP_METHODS:
        return None
    if not version.startswith("HTTP/"):
        return None

    headers = _parse_headers(lines[1:])
    body = _read_body(stream, head_end + 4, headers, body_limit)

    return HttpObject(
        kind="request",
        method=method,
        uri=uri,
        version=version.split("/", 1)[1],
        headers=headers,
        body=body[0],
        body_size=body[1],
        truncated=body[2],
        consumed=head_end + 4 + body[3],
    )


def parse_http_response(
    stream: bytes,
    body_limit: int = DEFAULT_BODY_LIMIT,
) -> HttpObject | None:
    """Разобрать HTTP-ответ из потока (или None)."""
    if not stream:
        return None

    head_end = stream.find(b"\r\n\r\n")
    if head_end < 0:
        return None

    header_block = stream[:head_end]
    try:
        header_text = header_block.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None

    lines = header_text.split("\r\n")
    if not lines:
        return None

    status_line = lines[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        return None
    if not parts[0].startswith("HTTP/"):
        return None
    try:
        status_code = int(parts[1])
    except ValueError:
        return None

    headers = _parse_headers(lines[1:])
    body = _read_body(stream, head_end + 4, headers, body_limit)

    return HttpObject(
        kind="response",
        version=parts[0].split("/", 1)[1],
        status_code=status_code,
        headers=headers,
        body=body[0],
        body_size=body[1],
        truncated=body[2],
        consumed=head_end + 4 + body[3],
    )


# ---------- keep-alive / pipelining ----------

DEFAULT_MAX_MESSAGES_PER_STREAM = 200


def _iter_messages(
    stream: bytes,
    parse,
    body_limit: int,
    max_messages: int,
):
    """Идти по потоку, пока парсер возвращает сообщения."""
    offset = 0
    for _ in range(max_messages):
        if offset >= len(stream):
            return
        obj = parse(stream[offset:], body_limit)
        if obj is None:
            return
        yield obj
        if obj.consumed <= 0:
            return
        offset += obj.consumed


def iter_http_requests(
    stream: bytes,
    body_limit: int = DEFAULT_BODY_LIMIT,
    max_messages: int = DEFAULT_MAX_MESSAGES_PER_STREAM,
):
    """
    Все HTTP-запросы в потоке, включая keep-alive и pipelining.

    Один TCP-поток может содержать несколько запросов подряд —
    раньше парсился только первый. Лимит max_messages защищает
    от патологических потоков.
    """
    return _iter_messages(
        stream, parse_http_request, body_limit, max_messages,
    )


def iter_http_responses(
    stream: bytes,
    body_limit: int = DEFAULT_BODY_LIMIT,
    max_messages: int = DEFAULT_MAX_MESSAGES_PER_STREAM,
):
    """Все HTTP-ответы в потоке (keep-alive, pipelining)."""
    return _iter_messages(
        stream, parse_http_response, body_limit, max_messages,
    )


# ---------- internals ----------

def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def _read_body(
    stream: bytes,
    body_start: int,
    headers: dict[str, str],
    body_limit: int,
) -> tuple[bytes, int, bool, int]:
    """
    Прочитать body из stream начиная с body_start.

    Возвращает (body, real_size, truncated, wire_len):
      - real_size — размер из заголовка (или len(body) если неизвестен)
      - truncated — True если body не влезло в body_limit
      - wire_len  — сколько байт потока занимает body (даже если body
                    вернулось обрезанным). Нужно, чтобы найти начало
                    следующего сообщения в keep-alive-соединении.
    """
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        body, size, truncated, end = _read_chunked(
            stream, body_start, body_limit,
        )
        return body, size, truncated, max(0, end - body_start)

    cl = headers.get("content-length")
    if cl is None:
        # Без Content-Length и без chunked — body отсутствует
        # (для запросов это норма, для ответов = соединение закроется)
        return b"", 0, False, 0

    try:
        expected = int(cl)
    except ValueError:
        return b"", 0, False, 0

    available = stream[body_start:]

    if len(available) >= expected:
        # Всё body в потоке
        if expected > body_limit:
            return available[:body_limit], expected, True, expected
        return available[:expected], expected, False, expected
    else:
        # Body пришло частично (обрыв, FIN, или лимит сработал)
        take = min(len(available), body_limit)
        return available[:take], expected, True, len(available)


def _read_chunked(
    stream: bytes,
    body_start: int,
    body_limit: int,
) -> tuple[bytes, int, bool, int]:
    """
    Разобрать chunked-encoded body. Возвращает распакованное тело.

    Формат: <size_hex>\r\n<data>\r\n<size_hex>\r\n<data>...0\r\n\r\n

    Четвёртый элемент — абсолютная позиция конца сообщения в stream.
    """
    pos = body_start
    out = bytearray()
    total_size = 0
    truncated = False

    while pos < len(stream):
        # Найти размер чанка
        eol = stream.find(b"\r\n", pos)
        if eol < 0:
            truncated = True
            break
        size_line = stream[pos:eol].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            truncated = True
            break

        pos = eol + 2

        if size == 0:
            # Последний чанк: после "0\r\n" идут либо "\r\n", либо trailer'ы
            after = pos
            if stream[after:after + 2] == b"\r\n":
                after += 2
            else:
                end = stream.find(b"\r\n\r\n", after)
                after = end + 4 if end >= 0 else after + 2
            return bytes(out[:body_limit]), total_size, truncated, after

        if pos + size > len(stream):
            # Чанк обрезан
            out.extend(stream[pos:])
            total_size += len(stream[pos:])
            truncated = True
            return bytes(out[:body_limit]), total_size, truncated, len(stream)

        out.extend(stream[pos:pos + size])
        total_size += size
        pos += size

        # Пропустить CRLF после чанка
        if pos + 2 <= len(stream) and stream[pos:pos + 2] == b"\r\n":
            pos += 2

        if len(out) >= body_limit:
            truncated = True
            return bytes(out[:body_limit]), total_size, truncated, len(stream)

    return bytes(out[:body_limit]), total_size, truncated, pos
