"""
Диагностика: SSH-активность в pcap.

Показывает все flows на порт 22 с разбивкой per src_ip.
Помогает отличить: brute-force (много коротких flows)
vs session (один длинный flow) vs scan (1-3 пакета).
"""
from collections import defaultdict
from scapy.utils import RawPcapReader

from pcap_triage.extractors.dns import DNSExtractor
from pcap_triage.extractors.flow import FlowExtractor
from pcap_triage.extractors.tls import TLSExtractor
from pcap_triage.models import CaptureState
from pcap_triage.parsers import parse_packet


PCAP = "C:/Users/a.grigoryev/Desktop/Новая папка (26)/Новая папка/CyberCampTask.pcap"


def main():
    state = CaptureState()
    extractors = [FlowExtractor(), DNSExtractor(), TLSExtractor()]

    reader = RawPcapReader(PCAP)
    for raw, meta in reader:
        ts = meta.sec + meta.usec / 1_000_000
        rec = parse_packet(raw, ts)
        for ex in extractors:
            try:
                ex.process(rec, state)
            except Exception:
                pass
    reader.close()

    # --- все flows к порту 22 ---
    ssh_flows = [
        (k, v) for k, v in state.flows.items() if k.dst_port == 22
    ]

    print(f"=== Flows к порту 22: {len(ssh_flows)} ===")
    for key, flow in sorted(ssh_flows, key=lambda kv: kv[1].first_ts or 0):
        print(
            f"  {key.src_ip}:{key.src_port} → {key.dst_ip}:{key.dst_port}  "
            f"pkts={flow.packets}  bytes={flow.bytes_sent}  "
            f"dur={flow.duration:.1f}s"
        )

    # --- агрегация per src_ip ---
    print()
    print("=== Агрегация per src_ip (dst_port=22) ===")
    by_src = defaultdict(lambda: {"flows": 0, "pkts": 0, "bytes": 0})
    for key, flow in ssh_flows:
        by_src[key.src_ip]["flows"] += 1
        by_src[key.src_ip]["pkts"] += flow.packets
        by_src[key.src_ip]["bytes"] += flow.bytes_sent

    for src, agg in sorted(by_src.items(), key=lambda kv: -kv[1]["flows"]):
        print(
            f"  {src}: {agg['flows']} flows, "
            f"{agg['pkts']} pkts, {agg['bytes']} bytes"
        )


if __name__ == "__main__":
    main()