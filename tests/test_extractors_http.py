"""
Unit-тесты HTTPExtractor.
"""
import pytest

from paradox.extractors.flow import FlowExtractor
from paradox.extractors.http import HTTPExtractor
from paradox.models import CaptureState, FlowKey
from paradox.parsers import PacketRecord


def _make_tcp_record(src_ip, dst_ip, sport, dport, payload):
    return PacketRecord(
        ts=1.0,
        length=54 + len(payload),
        raw=b"",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=sport,
        dst_port=dport,
        proto="tcp",
        payload=payload,
    )


def _make_request(method="GET", uri="/", host="example.com",
                  user_agent="Mozilla/5.0"):
    lines = [
        f"{method} {uri} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("latin-1")


# ---------- основной сценарий ----------

def test_http_extractor_writes_flow_fields():
    state = CaptureState()
    rec = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 80,
        _make_request(uri="/index.html", host="example.com"),
    )
    FlowExtractor().process(rec, state)
    HTTPExtractor().process(rec, state)

    key = FlowKey(proto="tcp", src_ip="192.168.1.100",
                  dst_ip="203.0.113.5", src_port=54000, dst_port=80)
    flow = state.flows[key]

    assert flow.http_method == "GET"
    assert flow.http_uri == "/index.html"
    assert flow.http_host == "example.com"
    assert flow.http_user_agent == "Mozilla/5.0"


def test_http_extractor_on_non_standard_port():
    """HTTP на 8080 — тоже ловим."""
    state = CaptureState()
    rec = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 8080,
        _make_request(uri="/admin"),
    )
    FlowExtractor().process(rec, state)
    HTTPExtractor().process(rec, state)

    key = FlowKey(proto="tcp", src_ip="192.168.1.100",
                  dst_ip="203.0.113.5", src_port=54000, dst_port=8080)
    assert state.flows[key].http_uri == "/admin"


# ---------- игнор ----------

def test_http_extractor_ignores_response():
    """Ответ сервера (HTTP/1.1 200 OK) — не запрос, не пишем."""
    state = CaptureState()
    rec = _make_tcp_record(
        "203.0.113.5", "192.168.1.100", 80, 54000,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    )
    FlowExtractor().process(rec, state)
    HTTPExtractor().process(rec, state)

    key = FlowKey(proto="tcp", src_ip="203.0.113.5",
                  dst_ip="192.168.1.100", src_port=80, dst_port=54000)
    assert state.flows[key].http_method is None


def test_http_extractor_ignores_tls():
    """TLS handshake — не HTTP."""
    state = CaptureState()
    rec = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 443,
        b"\x16\x03\x01\x00\x50\x01\x00\x00\x4c\x03\x03",
    )
    FlowExtractor().process(rec, state)
    HTTPExtractor().process(rec, state)

    key = FlowKey(proto="tcp", src_ip="192.168.1.100",
                  dst_ip="203.0.113.5", src_port=54000, dst_port=443)
    assert state.flows[key].http_method is None


def test_http_extractor_ignores_random_binary():
    """Бинарный мусор — не HTTP."""
    state = CaptureState()
    rec = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 80,
        b"\x00\x01\x02\x03\x04\x05",
    )
    FlowExtractor().process(rec, state)
    HTTPExtractor().process(rec, state)

    key = FlowKey(proto="tcp", src_ip="192.168.1.100",
                  dst_ip="203.0.113.5", src_port=54000, dst_port=80)
    assert state.flows[key].http_method is None


# ---------- перезапись ----------

def test_http_extractor_does_not_overwrite():
    """Второй HTTP-запрос в flow не перезаписывает первый."""
    state = CaptureState()
    rec1 = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 80,
        _make_request(uri="/first"),
    )
    rec2 = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 80,
        _make_request(uri="/second"),
    )
    FlowExtractor().process(rec1, state)
    HTTPExtractor().process(rec1, state)
    HTTPExtractor().process(rec2, state)

    key = FlowKey(proto="tcp", src_ip="192.168.1.100",
                  dst_ip="203.0.113.5", src_port=54000, dst_port=80)
    assert state.flows[key].http_uri == "/first"


# ---------- без flow ----------

def test_http_extractor_raises_without_flow():
    """Без FlowExtractor — явная ошибка."""
    state = CaptureState()
    rec = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 80,
        _make_request(),
    )

    with pytest.raises(RuntimeError, match="FlowExtractor"):
        HTTPExtractor().process(rec, state)


def test_http_extractor_skips_udp():
    state = CaptureState()
    rec = PacketRecord(
        ts=1.0, length=100, raw=b"",
        src_ip="a", dst_ip="b",
        src_port=100, dst_port=80,
        proto="udp",
        payload=_make_request(),
    )
    HTTPExtractor().process(rec, state)

    assert len(state.flows) == 0
