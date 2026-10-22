"""DNSExtractor собирает dns_query_ts_by_name (fix_30)."""
from paradox.extractors.dns import DNSExtractor
from paradox.models import CaptureState


def _build_dns_query_payload(qname: str) -> bytes:
    """Минимальный DNS query payload для scapy.DNS()."""
    # ID=0x1234, flags=0x0100 (RD), qdcount=1, затем qname
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = qname.encode("ascii").split(b".")
    qname_bytes = b"".join(bytes([len(lbl)]) + lbl for lbl in labels) + b"\x00"
    # QTYPE=A (1), QCLASS=IN (1)
    tail = b"\x00\x01\x00\x01"
    return header + qname_bytes + tail


def _build_record(payload, src_ip, dst_ip, src_port, dst_port, ts):
    """PacketRecord с заполненными полями для DNSExtractor."""
    from paradox.parsers import PacketRecord
    return PacketRecord(
        ts=ts, length=len(payload), raw=payload,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        proto="udp", payload=payload,
    )


def test_dns_extractor_collects_ts_by_name():
    state = CaptureState()
    extractor = DNSExtractor()
    payload = _build_dns_query_payload("evil.example.com")

    for i, ts in enumerate((100.0, 200.0, 300.0)):
        rec = _build_record(
            payload, "10.0.0.5", "8.8.8.8", 40000 + i, 53, ts,
        )
        extractor.process(rec, state)

    assert state.dns_queries["evil.example.com"] == 3
    assert state.dns_query_ts_by_name["evil.example.com"] == [
        100.0, 200.0, 300.0,
    ]


def test_dns_query_ts_multi_pcap_merge():
    """merge_capture_states сливает ts-списки."""
    from paradox.models import CaptureState
    from paradox.multi_pcap import merge_capture_states

    s1 = CaptureState()
    s1.dns_query_ts_by_name["evil.com"] = [100.0, 200.0]

    s2 = CaptureState()
    s2.dns_query_ts_by_name["evil.com"] = [300.0]

    merged = merge_capture_states([s1, s2])
    assert merged.dns_query_ts_by_name["evil.com"] == [
        100.0, 200.0, 300.0,
    ]
