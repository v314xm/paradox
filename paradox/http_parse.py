"""
Парсер HTTP-запроса.

Извлекает method, uri, host, user_agent из первой строки и заголовков
HTTP-запроса. Работает на сырых байтах payload.

Формат (RFC 7230):

  METHOD SP URI SP HTTP/VERSION CRLF
  Header-Name: value CRLF
  ...
  CRLF
  [body]

Поддерживается:
- HTTP/1.0, HTTP/1.1
- методы GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
- заголовки Host и User-Agent (регистронезависимо)

Не поддерживается:
- HTTP/2 (бинарный формат)
- HTTP/3
- Ответы сервера (только запросы)
- Многострочные заголовки (continuation lines)
"""
from __future__ import annotations

from dataclasses import dataclass


HTTP_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "DELETE",
    "CONNECT", "OPTIONS", "TRACE", "PATCH",
})

# максимальный размер блока заголовков — защита от мусора
MAX_HEADER_BYTES = 8192

# максимум заголовков — защита от флуда
MAX_HEADERS = 64


@dataclass
class HTTPRequest:
    method: str
    uri: str
    version: str
    host: str | None = None
    user_agent: str | None = None


def parse_request(payload: bytes) -> HTTPRequest | None:
    """
    Разобрать HTTP-запрос из payload TCP-пакета.

    Возвращает HTTPRequest или None, если это не HTTP-запрос.
    """
    if not payload:
        return None

    # отрезаем тело запроса — работаем с блоком заголовков
    header_end = payload.find(b"\r\n\r\n")
    if header_end == -1:
        # заголовки могут быть обрезаны (фрагментация)
        header_bytes = payload[:MAX_HEADER_BYTES]
    else:
        header_bytes = payload[:header_end]

    try:
        text = header_bytes.decode("latin-1")
    except UnicodeDecodeError:
        return None

    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None

    # --- первая строка ---
    request_line = lines[0]
    parts = request_line.split(" ", 2)
    if len(parts) < 3:
        return None

    method, uri, version = parts
    if method not in HTTP_METHODS:
        return None
    if not version.startswith("HTTP/"):
        return None

    req = HTTPRequest(method=method, uri=uri, version=version)

    # --- заголовки ---
    for line in lines[1:MAX_HEADERS + 1]:
        if not line:
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name_lower = name.strip().lower()
        value = value.strip()

        if name_lower == "host" and req.host is None:
            req.host = value.lower()
        elif name_lower == "user-agent" and req.user_agent is None:
            req.user_agent = value

    return req