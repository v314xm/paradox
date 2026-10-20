"""Тесты DNS-экстрактора."""
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
from paradox.models import CaptureState
from paradox.parsers import PacketRecord
from paradox.extractors.dns import DNSExtractor


def _make_dns_record(qname: str, rcode: int = 0, answers: list | None = None) -> PacketRecord:
    """Собирает PacketRecord из реального DNS-пакета."""
    if answers:
        dns = DNS(qd=DNSQR(qname=qname), an=answers, rcode=rcode)
    else:
        dns = DNS(qd=DNSQR(qname=qname), rcode=rcode)

    pkt = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=12345, dport=53) / dns

    return PacketRecord(
        ts=100.0,
        length=len(pkt),
        raw=bytes(pkt),
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        proto="udp",
        src_port=12345,
        dst_port=53,
        payload=bytes(pkt[UDP].payload),
    )


def test_dns_query_recorded():
    """Обычный DNS-запрос сохраняется в state."""
    record = _make_dns_record("example.com")
    state = CaptureState()
    DNSExtractor().process(record, state)

    assert state.dns_queries["example.com"] == 1
    assert state.dns_queries_by_src["10.0.0.5"]["example.com"] == 1


def test_dns_nxdomain_recorded():
    """NXDOMAIN увеличивает dns_nxdomain и dns_nxdomain_ts_by_src."""
    record = _make_dns_record("nonexistent.invalid", rcode=3)
    state = CaptureState()
    DNSExtractor().process(record, state)

    assert state.dns_nxdomain["nonexistent.invalid"] == 1
    assert state.dns_nxdomain_by_src["10.0.0.5"] == 1
    assert len(state.dns_nxdomain_ts_by_src["10.0.0.5"]) == 1


def test_dns_non_ascii_ignored():
    """Битый qname (не ASCII) — не падаем и не сохраняем."""
    # Явные MAC обязательны: без них Scapy резолвит interface
    # (на Windows — "Microsoft KM-TEST Loopback Adapter", которого
    # может не быть), и Ether().build() падает с ValueError.
    dns = DNS(qd=DNSQR(qname=b"\xff\xfe.bad"))
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / dns
    )
    record = PacketRecord(
        ts=100.0, length=len(pkt), raw=bytes(pkt),
        src_ip="10.0.0.5", dst_ip="8.8.8.8",
        proto="udp", src_port=12345, dst_port=53,
        payload=bytes(pkt[UDP].payload),
    )

    state = CaptureState()
    DNSExtractor().process(record, state)
    assert len(state.dns_queries) == 0