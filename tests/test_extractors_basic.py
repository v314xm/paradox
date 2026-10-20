from scapy.all import ARP, DNS, DNSQR, IP, UDP, Ether

from paradox.extractors.arp_history import ARPMacHistoryExtractor
from paradox.extractors.dns import DNSExtractor
from paradox.models import CaptureState
from paradox.parsers import PacketRecord


def test_dns_extractor_a_record():
    # Генерим реальный DNS-запрос через Scapy
    pkt = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(qd=DNSQR(qname="example.com"))

    # Создаем PacketRecord вручную, имитируя парсер
    record = PacketRecord(
        ts=100.0,
        length=len(pkt),
        raw=bytes(pkt),
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        proto="udp",
        src_port=12345,
        dst_port=53,
        payload=bytes(pkt[UDP].payload)  # DNS-часть
    )

    state = CaptureState()
    DNSExtractor().process(record, state)

    assert "example.com" in state.dns_queries
    assert state.dns_queries["example.com"] == 1
    assert "10.0.0.5" in state.dns_queries_by_src


def test_arp_history_extractor():
    pkt = Ether() / ARP(op=1, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff", pdst="192.168.1.1")

    record = PacketRecord(
        ts=200.0,
        length=len(pkt),
        raw=bytes(pkt),
        proto="arp",
        arp_op=1,
        arp_sender_ip="192.168.1.10",
        arp_sender_mac="aa:bb:cc:dd:ee:ff"
    )

    state = CaptureState()
    ARPMacHistoryExtractor().process(record, state)

    assert "192.168.1.10" in state.arp_macs
    assert "aa:bb:cc:dd:ee:ff" in state.arp_macs["192.168.1.10"]
    assert state.arp_macs["192.168.1.10"]["aa:bb:cc:dd:ee:ff"][2] == 1  # count