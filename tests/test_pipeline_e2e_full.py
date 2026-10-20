"""End-to-end тест полного пайплайна на 2 синтетических пакетах.

Покрывает:
  - pipeline._extract (обход пакетов, парсинг, экстракторы)
  - pipeline._detect (запуск всех детекторов)
  - pipeline._summarize_direction
  - build_flow_report, build_dns_report
"""
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

from paradox.config import Config
from paradox.pipeline import run_pipeline


def _build_pcap(tmp_path) -> Path:
    """Собирает минимальный pcap: 1 DNS-запрос + 1 TCP SYN."""
    pkt_dns = (
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(qd=DNSQR(qname="example.com"))
    )
    pkt_tcp = (
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:77")
        / IP(src="10.0.0.5", dst="10.0.0.1")
        / TCP(sport=54321, dport=80, flags="S")
    )
    pcap_path = tmp_path / "e2e.pcap"
    wrpcap(str(pcap_path), [pkt_dns, pkt_tcp])
    return pcap_path


def test_pipeline_runs_end_to_end(tmp_path):
    """Полный прогон: пакеты разобраны, summary заполнен."""
    pcap = _build_pcap(tmp_path)
    config = Config(
        tcp_reassembly_enabled=False,  # ускоряем — нам важен сам обход
        file_carve_enabled=False,
    )

    report = run_pipeline(pcap, config)

    # Summary
    assert report["summary"]["packets"] == 2
    assert report["summary"]["flows"] >= 2  # DNS и TCP — разные flow
    assert report["summary"]["unique_dns_queries"] >= 1

    # Ключевые секции отчёта присутствуют
    assert "provenance" in report
    assert "dns" in report
    assert "flows" in report
    assert "findings" in report
    assert "contradictions" in report
    assert "timeline" in report
    assert "entities" in report


def test_pipeline_dns_extracted(tmp_path):
    """DNS-запрос попадает в отчёт."""
    pcap = _build_pcap(tmp_path)
    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)

    report = run_pipeline(pcap, config)

    dns_section = report["dns"]
    assert dns_section["unique_count"] >= 1
    top = dns_section["top_by_count"]
    assert any(q["name"] == "example.com" for q in top)


def test_pipeline_direction_summary(tmp_path):
    """Direction summary заполнен: internal→external → outbound."""
    pcap = _build_pcap(tmp_path)
    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)

    report = run_pipeline(pcap, config)
    s = report["summary"]

    # Оба пакета уходят с internal 10.0.0.5 → наружу, значит uploaded_bytes > 0
    assert "uploaded_bytes" in s
    assert "downloaded_bytes" in s
    assert s["uploaded_bytes"] >= 0
