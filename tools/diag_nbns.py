"""Диагностика NBNS-экстрактора с логированием ошибок."""
from scapy.utils import RawPcapReader

from pcap_triage.models import CaptureState
from pcap_triage.parsers import parse_packet
from pcap_triage.pipeline import EXTRACTORS

PCAP = r'C:\Users\a.grigoryev\Downloads\2025-06-13-traffic-analysis-exercise.pcap\2025-06-13-traffic-analysis-exercise.pcap'

state = CaptureState()
reader = RawPcapReader(PCAP)

extractor_errors = {}
shown_errors = {}

for raw, meta in reader:
    ts = meta.sec + meta.usec / 1_000_000
    record = parse_packet(raw, ts)

    for ex in EXTRACTORS:
        try:
            ex.process(record, state)
        except Exception as e:
            name = ex.name
            extractor_errors[name] = extractor_errors.get(name, 0) + 1
            if shown_errors.get(name, 0) < 3:
                shown_errors[name] = shown_errors.get(name, 0) + 1
                print(f"ERROR [{name}]: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()

reader.close()

print()
print(f"Extractor errors: {extractor_errors}")
print()
print("host_identities с hostnames:")
for ip, h in state.host_identities.items():
    if h.hostnames:
        print(f"  {ip}: mac={h.mac}, hostnames={h.hostnames}")