"""Тесты DNSExtractor: A/AAAA/CNAME, NXDOMAIN, битые пакеты, ts (fix_30)."""
from paradox.extractors.dns import DNSExtractor
from paradox.models import CaptureState
from paradox.parsers import PacketRecord


def _build_dns_query(qname: str, qtype: int = 1) -> bytes:
    """DNS query: header + qname + qtype + qclass."""
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = qname.encode("ascii").split(b".")
    qname_bytes = b"".join(bytes([len(lbl)]) + lbl for lbl in labels) + b"\x00"
    return header + qname_bytes + qtype.to_bytes(2, "big") + b"\x00\x01"


def _build_dns_response(
    qname: str, answer_type: int | None, rdata: bytes, rcode: int = 0,
) -> bytes:
    """DNS response с одной answer-записью.

    rcode=3 → NXDOMAIN.
    answer_type=None → без answer-секции (правильный NXDOMAIN по RFC 2308).
    answer_type: 1=A, 28=AAAA, 5=CNAME, 16=TXT (последний не парсится).
    """
    flags = 0x8180 if rcode == 0 else 0x8183
    ancount = 1 if answer_type is not None else 0
    header = (
        b"\x12\x34" + flags.to_bytes(2, "big") +
        b"\x00\x01" + ancount.to_bytes(2, "big") + b"\x00\x00" + b"\x00\x00"
    )
    labels = qname.encode("ascii").split(b".")
    qname_bytes = b"".join(bytes([len(lbl)]) + lbl for lbl in labels) + b"\x00"
    question = qname_bytes + b"\x00\x01\x00\x01"
    if answer_type is None:
        return header + question
    answer = (
        b"\xc0\x0c" + answer_type.to_bytes(2, "big") +
        b"\x00\x01" + b"\x00\x00\x00\x3c" +
        len(rdata).to_bytes(2, "big") + rdata
    )
    return header + question + answer


def _record(payload: bytes, src_ip: str, dst_ip: str,
            src_port: int, dst_port: int, ts: float = 100.0) -> PacketRecord:
    return PacketRecord(
        ts=ts, length=len(payload), raw=payload,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        proto="udp", payload=payload,
    )


# ================== базовые сценарии ==================

def test_dns_query_collected_by_src():
    state = CaptureState()
    payload = _build_dns_query("example.com")
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert state.dns_queries["example.com"] == 1
    assert state.dns_queries_by_src["10.0.0.5"]["example.com"] == 1


def test_dns_query_from_server_side_uses_dst_as_client():
    state = CaptureState()
    payload = _build_dns_query("example.com")
    DNSExtractor().process(
        _record(payload, "8.8.8.8", "10.0.0.5", 53, 40000), state,
    )
    assert "10.0.0.5" in state.dns_queries_by_src
    assert "8.8.8.8" not in state.dns_queries_by_src


def test_nxdomain_counted_by_src_and_ts():
    state = CaptureState()
    payload = _build_dns_response(
        "bad.dga.com", answer_type=None, rdata=b"", rcode=3,
    )
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53, ts=200.0),
        state,
    )
    assert state.dns_nxdomain["bad.dga.com"] == 1
    assert state.dns_nxdomain_by_src["10.0.0.5"] == 1
    assert state.dns_nxdomain_ts_by_src["10.0.0.5"] == [200.0]


# ================== A / AAAA / CNAME ответы ==================

def test_a_record_fills_answers_by_name_and_ip():
    state = CaptureState()
    payload = _build_dns_response(
        "example.com", answer_type=1, rdata=b"\x01\x02\x03\x04",
    )
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert "1.2.3.4" in state.dns_answers_by_name["example.com"]
    assert "example.com" in state.dns_answers_by_ip["1.2.3.4"]


def test_aaaa_record_fills_answers_by_name():
    state = CaptureState()
    ipv6 = bytes.fromhex("20010db8000000000000000000000001")
    payload = _build_dns_response(
        "example.com", answer_type=28, rdata=ipv6,
    )
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert any("2001:db8" in v.lower() for v in
               state.dns_answers_by_name["example.com"])


def test_cname_record_fills_answers_by_name():
    state = CaptureState()
    cname_target = b"\x03cdn\x07example\x03com\x00"
    payload = _build_dns_response(
        "www.example.com", answer_type=5, rdata=cname_target,
    )
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert "cdn.example.com" in state.dns_answers_by_name["www.example.com"]


def test_unsupported_answer_type_ignored():
    state = CaptureState()
    payload = _build_dns_response(
        "example.com", answer_type=16, rdata=b"\x05hello",
    )
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert "example.com" in state.dns_queries
    assert "example.com" not in state.dns_answers_by_name


# ================== защита от мусора ==================

def test_non_ascii_qname_skipped():
    state = CaptureState()
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    payload += b"\x05" + b"\xff\xfe\xfd\xfc\xfb" + b"\x00\x00\x01\x00\x01"
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert len(state.dns_queries) == 0


def test_invalid_chars_in_qname_skipped():
    state = CaptureState()
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    payload += b"\x05a!b@c" + b"\x00\x00\x01\x00\x01"
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert len(state.dns_queries) == 0


def test_empty_payload_skipped():
    state = CaptureState()
    DNSExtractor().process(
        _record(b"", "10.0.0.5", "8.8.8.8", 40000, 53), state,
    )
    assert len(state.dns_queries) == 0


def test_non_dns_port_skipped():
    state = CaptureState()
    payload = _build_dns_query("example.com")
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "1.2.3.4", 40000, 80), state,
    )
    assert len(state.dns_queries) == 0


# ================== dns_query_ts_by_name (fix_30) ==================

def test_dns_query_ts_collected():
    state = CaptureState()
    payload = _build_dns_query("evil.com")
    for i, ts in enumerate((100.0, 200.0)):
        DNSExtractor().process(
            _record(payload, "10.0.0.5", "8.8.8.8", 40000 + i, 53, ts),
            state,
        )
    assert state.dns_query_ts_by_name["evil.com"] == [100.0, 200.0]
def test_broken_rr_does_not_break_extractor():
    """Регрессия fix_33: битый RR не должен ломать парсинг пакета.

    NXDOMAIN с answer-секцией, где RR имеет rdlength=0 и неизвестный
    тип, роняет rr.type. try/except сохраняет NXDOMAIN-подсчёт.
    """
    state = CaptureState()
    # NXDOMAIN + 1 answer с типом A и пустым rdata (крафтовый/битый)
    payload = _build_dns_response(
        "bad.dga.com", answer_type=1, rdata=b"", rcode=3,
    )
    # Не падаем, NXDOMAIN засчитан, RR пропущен
    DNSExtractor().process(
        _record(payload, "10.0.0.5", "8.8.8.8", 40000, 53, ts=200.0),
        state,
    )
    assert state.dns_nxdomain["bad.dga.com"] == 1
    assert state.dns_nxdomain_by_src["10.0.0.5"] == 1
    assert state.dns_nxdomain_ts_by_src["10.0.0.5"] == [200.0]
    # answers не заполнены, потому что RR не парсится
    assert "bad.dga.com" not in state.dns_answers_by_name
