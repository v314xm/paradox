"""
Unit-тесты TLSExtractor.

Работаем с PacketRecord и CaptureState напрямую. Никакого pcap.
"""
import pytest

from paradox.extractors.flow import FlowExtractor
from paradox.extractors.tls import TLSExtractor
from paradox.models import CaptureState, FlowKey
from paradox.parsers import PacketRecord


# минимальный валидный ClientHello с example.com
def _build_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    name_entry = (
        b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    )
    server_name_list = len(name_entry).to_bytes(2, "big") + name_entry
    server_name_ext = (
        b"\x00\x00"
        + len(server_name_list).to_bytes(2, "big")
        + server_name_list
    )
    extensions_block = (
        len(server_name_ext).to_bytes(2, "big") + server_name_ext
    )
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + extensions_block
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _make_tcp_record(
    src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes,
) -> PacketRecord:
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


# ---------- основной сценарий ----------

def test_tls_extractor_writes_sni():
    state = CaptureState()
    flow_ext = FlowExtractor()
    tls_ext = TLSExtractor()

    rec = _make_tcp_record(
        "192.168.1.100", "203.0.113.5", 54000, 443,
        _build_client_hello("example.com"),
    )

    flow_ext.process(rec, state)
    tls_ext.process(rec, state)

    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.100", dst_ip="203.0.113.5",
        src_port=54000, dst_port=443,
    )
    assert state.flows[key].sni == "example.com"


def test_tls_extractor_on_non_standard_port():
    """TLS на нестандартном порту — тоже ловим."""
    state = CaptureState()
    FlowExtractor().process(
        _make_tcp_record("a", "b", 100, 8443, b""), state,
    )
    rec = _make_tcp_record(
        "a", "b", 100, 8443, _build_client_hello("c2.evil.com"),
    )
    FlowExtractor().process(rec, state)
    TLSExtractor().process(rec, state)

    key = FlowKey(proto="tcp", src_ip="a", dst_ip="b",
                  src_port=100, dst_port=8443)
    assert state.flows[key].sni == "c2.evil.com"


# ---------- edge cases ----------

def test_tls_extractor_ignores_non_tls():
    state = CaptureState()
    FlowExtractor().process(
        _make_tcp_record("a", "b", 100, 80, b"GET / HTTP/1.1\r\n"),
        state,
    )
    TLSExtractor().process(
        _make_tcp_record("a", "b", 100, 80, b"GET / HTTP/1.1\r\n"),
        state,
    )

    key = FlowKey(proto="tcp", src_ip="a", dst_ip="b",
                  src_port=100, dst_port=80)
    assert state.flows[key].sni is None


def test_tls_extractor_does_not_overwrite_sni():
    """Второе ClientHello не перезаписывает уже установленный SNI."""
    state = CaptureState()
    rec1 = _make_tcp_record(
        "a", "b", 100, 443, _build_client_hello("first.com"),
    )
    rec2 = _make_tcp_record(
        "a", "b", 100, 443, _build_client_hello("second.com"),
    )
    FlowExtractor().process(rec1, state)
    TLSExtractor().process(rec1, state)
    TLSExtractor().process(rec2, state)

    key = FlowKey(proto="tcp", src_ip="a", dst_ip="b",
                  src_port=100, dst_port=443)
    assert state.flows[key].sni == "first.com"


def test_tls_extractor_raises_without_flow():
    """Если FlowExtractor не запускался — TLSExtractor падает явно."""
    state = CaptureState()
    rec = _make_tcp_record(
        "a", "b", 100, 443, _build_client_hello("example.com"),
    )

    with pytest.raises(RuntimeError, match="FlowExtractor"):
        TLSExtractor().process(rec, state)


def test_tls_extractor_skips_udp():
    state = CaptureState()
    rec = PacketRecord(
        ts=1.0, length=100, raw=b"",
        src_ip="a", dst_ip="b",
        src_port=100, dst_port=443,
        proto="udp",
        payload=_build_client_hello("example.com"),
    )

    TLSExtractor().process(rec, state)

    # никаких падений, никаких flows
    assert len(state.flows) == 0
