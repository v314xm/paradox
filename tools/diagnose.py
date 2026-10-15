"""
Диагностический скрипт: проверяем, есть ли C2-домены в dns_queries.
Запускается отдельно от pipeline, читает pcap сам.
"""
from scapy.utils import RawPcapReader

from pcap_triage.extractors.dns import DNSExtractor
from pcap_triage.extractors.flow import FlowExtractor
from pcap_triage.extractors.tls import TLSExtractor
from pcap_triage.models import CaptureState
from pcap_triage.parsers import parse_packet


EXTRACTORS = [FlowExtractor(), DNSExtractor(), TLSExtractor()]


def main():
    pcap = "C:/Users/a.grigoryev/Desktop/Новая папка (26)/Новая папка/CyberCampTask.pcap"
    state = CaptureState()

    reader = RawPcapReader(pcap)
    for raw, meta in reader:
        ts = meta.sec + meta.usec / 1_000_000
        rec = parse_packet(raw, ts)
        for ex in EXTRACTORS:
            try:
                ex.process(rec, state)
            except Exception:
                pass
    reader.close()

    print()
    print("=== rtbcdn в dns_queries ===")
    found_rtbcdn = False
    for name, count in state.dns_queries.items():
        if "rtbcdn" in name:
            print(f"  {name}: {count}")
            found_rtbcdn = True
    if not found_rtbcdn:
        print("  (не найдено)")

    print()
    print("=== smartscreen / nav-edge в dns_queries ===")
    found_smart = False
    for name, count in state.dns_queries.items():
        if "smartscreen" in name or "nav-edge" in name:
            print(f"  {name}: {count}")
            found_smart = True
    if not found_smart:
        print("  (не найдено)")

    print()
    print(f"=== всего уникальных dns_queries: {len(state.dns_queries)} ===")

    # соберём все SNI из flows
    print()
    print("=== все rtbcdn SNI в flows ===")
    rtbcdn_snis = set()
    for key, flow in state.flows.items():
        if flow.sni and "rtbcdn" in flow.sni:
            rtbcdn_snis.add(flow.sni)
    for sni in sorted(rtbcdn_snis):
        print(f"  {sni}")

    # сверим: SNI vs dns_queries
    print()
    print("=== проверка SNIMismatch логики ===")
    for sni in sorted(rtbcdn_snis):
        in_dns = sni in state.dns_queries
        print(f"  {sni}: in_dns={in_dns}")


if __name__ == "__main__":
    main()