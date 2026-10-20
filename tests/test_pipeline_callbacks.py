"""Тесты callbacks в run_pipeline: on_progress, on_phase, should_stop."""
from unittest.mock import MagicMock

from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

from paradox.config import Config
from paradox.pipeline import run_pipeline


def _build_pcap(tmp_path):
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(qd=DNSQR(qname="example.com"))
    )
    pcap_path = tmp_path / "cb.pcap"
    wrpcap(str(pcap_path), [pkt])
    return pcap_path


def test_pipeline_on_progress_called(tmp_path):
    """on_progress вызывается хотя бы один раз в конце (100%)."""
    pcap = _build_pcap(tmp_path)
    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    on_progress = MagicMock()

    run_pipeline(pcap, config, on_progress=on_progress)

    assert on_progress.called
    # Последний вызов — с bytes_read == total_bytes
    args, _ = on_progress.call_args_list[-1]
    assert args[0] == args[1]


def test_pipeline_on_phase_called(tmp_path):
    """on_phase вызывается для detect / contradictions / report."""
    pcap = _build_pcap(tmp_path)
    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    on_phase = MagicMock()

    run_pipeline(pcap, config, on_phase=on_phase)

    phases = [call.args[0] for call in on_phase.call_args_list]
    assert "detect" in phases
    assert "contradictions" in phases
    assert "report" in phases


def test_pipeline_should_stop_not_triggered(tmp_path):
    """should_stop=lambda: False — проходит весь pcap."""
    pcap = _build_pcap(tmp_path)
    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)

    report = run_pipeline(pcap, config, should_stop=lambda: False)
    assert report["summary"]["packets"] == 1
