"""
Тесты парсера HTTP-объектов.

Body читается из потока по Content-Length / chunked.
"""
from pcap_triage.http_object import (
    parse_http_request,
    parse_http_response,
)


def test_simple_get_request():
    raw = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: TestAgent/1.0\r\n"
        b"\r\n"
    )
    obj = parse_http_request(raw)
    assert obj is not None
    assert obj.kind == "request"
    assert obj.method == "GET"
    assert obj.uri == "/index.html"
    assert obj.version == "1.1"
    assert obj.headers["host"] == "example.com"
    assert obj.headers["user-agent"] == "TestAgent/1.0"
    assert obj.body == b""


def test_post_with_body():
    body = b"username=admin&password=secret"
    raw = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n"
        + body
    )
    obj = parse_http_request(raw)
    assert obj is not None
    assert obj.method == "POST"
    assert obj.body == body
    assert obj.body_size == len(body)
    assert not obj.truncated


def test_response_with_body():
    body = b"<html>Hello</html>"
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n"
        + body
    )
    obj = parse_http_response(raw)
    assert obj is not None
    assert obj.kind == "response"
    assert obj.status_code == 200
    assert obj.body == body


def test_response_404():
    raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    obj = parse_http_response(raw)
    assert obj is not None
    assert obj.status_code == 404


def test_chunked_response():
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nHello\r\n"
        b"6\r\n World\r\n"
        b"0\r\n\r\n"
    )
    obj = parse_http_response(raw)
    assert obj is not None
    assert obj.body == b"Hello World"
    assert not obj.truncated


def test_body_truncated_by_limit():
    big_body = b"A" * 5000
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 5000\r\n"
        b"\r\n"
        + big_body
    )
    obj = parse_http_response(raw, body_limit=1000)
    assert obj is not None
    assert len(obj.body) == 1000
    assert obj.body_size == 5000
    assert obj.truncated


def test_not_http_request():
    # Бинарные данные — не HTTP
    assert parse_http_request(b"\x16\x03\x01\x00\x05hello") is None
    assert parse_http_request(b"") is None
    assert parse_http_request(b"random bytes") is None


def test_not_http_response():
    assert parse_http_response(b"GET / HTTP/1.1\r\n\r\n") is None
    assert parse_http_response(b"") is None
    assert parse_http_response(b"garbage") is None


def test_incomplete_headers_returns_none():
    # Заголовки не завершены (\r\n\r\n нет)
    assert parse_http_request(b"GET / HTTP/1.1\r\nHost: x") is None
    assert parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5") is None


def test_body_not_all_received():
    # Content-Length больше, чем в потоке
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 1000\r\n"
        b"\r\n"
        b"only part"
    )
    obj = parse_http_response(raw)
    assert obj is not None
    assert obj.body == b"only part"
    assert obj.body_size == 1000
    assert obj.truncated


def test_case_insensitive_headers():
    raw = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"CONTENT-LENGTH: 0\r\n"
        b"\r\n"
    )
    obj = parse_http_request(raw)
    assert obj is not None
    assert obj.headers["host"] == "example.com"
    assert obj.headers["content-length"] == "0"


def test_chunked_request():
    raw = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"4\r\nabcd\r\n"
        b"3\r\nefg\r\n"
        b"0\r\n\r\n"
    )
    obj = parse_http_request(raw)
    assert obj is not None
    assert obj.method == "POST"
    assert obj.body == b"abcdefg"