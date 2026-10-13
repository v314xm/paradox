from pathlib import Path
from pcap_triage.config import Config
from pcap_triage.models import CaptureState
from pcap_triage.pipeline import _extract

base = Path(r"C:\Users\a.grigoryev\Downloads\FIRST-2015_Hands-on_Network_Forensics_PCAP")
samples = [
    base / "2015-03-05" / "snort.log.1425568941",
    base / "2015-03-17" / "snort.log.1426550408",
    base / "2015-04-13" / "snort.log.1428883207",
]
for f in samples:
    if not f.exists():
        print(f"skip (not found): {f.name}")
        continue
    s = CaptureState()
    _extract(f, s, Config())
    multi = [ip for ip, macs in s.arp_macs.items() if len(macs) > 1]
    print(f"{f.name}: arp_ips={len(s.arp_macs)} multi_mac={len(multi)}")
    for ip in multi:
        print(f"  {ip}: {list(s.arp_macs[ip].keys())}")
