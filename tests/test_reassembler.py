"""
Тесты TCPReassembler.

Проверяем:
- Basic: 3 сегмента в порядке → склейка
- Out-of-order: приходят в разном порядке → тот же результат
- Retransmit: дубликат offset игнорируется
- SYN-based base_seq
- Mid-stream (без SYN)
- Truncation (лимит per-flow)
- FIN финализирует
- RST финализирует
- empty payload не хранится
- stats()
"""
from paradox.reassembler import TCPReassembler


def _pkt(
    src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80,
    seq=0, flags=0, payload=b"", proto="tcp",
):
    """Минимальный PacketRecord-like объект."""
    from paradox.parsers import PacketRecord
    return PacketRecord(
        ts=0.0, length=0, raw=b"",
        eth_src=None, eth_dst=None, ethertype=0, vlan_id=None,
        src_ip=src, dst_ip=dst, ip_proto=6, ip_id=0,
        ip_frag_offset=0, ip_mf=False,
        proto=proto, src_port=sport, dst_port=dport,
        tcp_seq=seq, tcp_ack=None, tcp_flags=flags,
        arp_op=None, arp_sender_mac=None, arp_sender_ip=None,
        arp_target_mac=None, arp_target_ip=None,
        payload=payload,
    )


def test_basic_in_order():
    """3 сегмента в правильном порядке."""
    r = TCPReassembler()
    r.feed(_pkt(flags=0x02, seq=1000))  # SYN
    r.feed(_pkt(seq=1001, payload=b"hello "))
    r.feed(_pkt(seq=1007, payload=b"world"))
    r.feed(_pkt(seq=1012, payload=b"!", flags=0x01))  # FIN
    r.finalize_all()

    from paradox.models import FlowKey
    key = FlowKey(proto="tcp", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                  src_port=50000, dst_port=80)
    assert r.all_streams()[key] == b"hello world!"


def test_out_of_order():
    """Сегменты приходят вразнобой — результат тот же."""
    r = TCPReassembler()
    r.feed(_pkt(flags=0x02, seq=1000))
    r.feed(_pkt(seq=1012, payload=b"!"))
    r.feed(_pkt(seq=1001, payload=b"hello "))
    r.feed(_pkt(seq=1007, payload=b"world"))
    r.finalize_all()

    from paradox.models import FlowKey
    key = FlowKey(proto="tcp", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                  src_port=50000, dst_port=80)
    assert r.all_streams()[key] == b"hello world!"


def test_retransmit_ignored():
    """Дубликат offset — второй payload не перезаписывает первый."""
    r = TCPReassembler()
    r.feed(_pkt(flags=0x02, seq=1000))
    r.feed(_pkt(seq=1001, payload=b"AAAA"))
    r.feed(_pkt(seq=1001, payload=b"BBBB"))  # retransmit с тем же offset
    r.finalize_all()

    from paradox.models import FlowKey
    key = FlowKey(proto="tcp", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                  src_port=50000, dst_port=80)
    assert r.all_streams()[key] == b"AAAA"


def test_mid_stream_no_syn():
    """Без SYN — первый увиденный seq становится базой."""
    r = TCPReassembler()
    r.feed(_pkt(seq=5000, payload=b"abc"))
    r.feed(_pkt(seq=5003, payload=b"def"))
    r.finalize_all()

    from paradox.models import FlowKey
    key = FlowKey(proto="tcp", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                  src_port=50000, dst_port=80)
    assert r.all_streams()[key] == b"abcdef"


def test_truncation_per_flow():
    """Превышение лимита per-flow — поток в truncated."""
    r = TCPReassembler(max_bytes_per_flow=10)
    r.feed(_pkt(flags=0x02, seq=1000))
    r.feed(_pkt(seq=1001, payload=b"123456"))  # 6 байт, ок
    r.feed(_pkt(seq=1007, payload=b"123456"))  # ещё 6, превысит 10
    r.finalize_all()

    from paradox.models import FlowKey
    key = FlowKey(proto="tcp", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                  src_port=50000, dst_port=80)
    assert key in r.truncated_flows()


def test_rst_finalizes():
    """RST финализирует поток."""
    r = TCPReassembler()
    r.feed(_pkt(flags=0x02, seq=1000))
    r.feed(_pkt(seq=1001, payload=b"data"))
    r.feed(_pkt(flags=0x04))  # RST

    from paradox.models import FlowKey
    key = FlowKey(proto="tcp", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                  src_port=50000, dst_port=80)
    assert r.all_streams()[key] == b"data"


def test_empty_payload_not_stored():
    """Пакет без payload не создаёт буфер."""
    r = TCPReassembler()
    r.feed(_pkt(flags=0x02, seq=1000))  # SYN без payload
    r.finalize_all()
    assert r.all_streams() == {}


def test_udp_ignored():
    """UDP не обрабатывается."""
    r = TCPReassembler()
    r.feed(_pkt(proto="udp", seq=None, payload=b"x"))
    r.finalize_all()
    assert r.all_streams() == {}


def test_stats():
    """stats() возвращает сводку."""
    r = TCPReassembler()
    r.feed(_pkt(flags=0x02, seq=1000))
    r.feed(_pkt(seq=1001, payload=b"hi"))
    r.finalize_all()
    s = r.stats()
    assert s["streams_total"] == 1
    assert s["streams_truncated"] == 0
    assert s["bytes_total"] == 2
