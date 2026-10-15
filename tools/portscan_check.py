"""Диагностика: сколько dst_port с одного src_ip к одному dst_ip."""
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

    # агрегация: (src_ip, dst_ip) → set(dst_port), flows, packets
    agg = defaultdict(lambda: {
        "dst_ports": set(),
        "flows": 0,
        "packets": 0,
    })

    for key, flow in state.flows.items():
        if key.proto != "tcp" or key.dst_port is None:
            continue
        bucket = agg[(key.src_ip, key.dst_ip)]
        bucket["dst_ports"].add(key.dst_port)
        bucket["flows"] += 1
        bucket["packets"] += flow.packets

    # сортировка по числу уникальных портов
    rows = []
    for (src, dst), b in agg.items():
        avg = b["packets"] / b["flows"] if b["flows"] else 0
        rows.append((src, dst, len(b["dst_ports"]), b["flows"], avg))

    rows.sort(key=lambda r: -r[2])

    print(f"{'src':<15} {'dst':<15} {'ports':>6} {'flows':>6} {'avg_pkt':>8}")
    print("-" * 55)
    for src, dst, ports, flows, avg in rows[:20]:
        print(f"{src:<15} {dst:<15} {ports:>6} {flows:>6} {avg:>8.1f}")


if __name__ == "__main__":
    main()