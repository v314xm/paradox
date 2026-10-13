from pathlib import Path
from pcap_triage.config import Config
from pcap_triage.models import CaptureState
from pcap_triage.pipeline import _extract
from pcap_triage.contradictions.facts import extract_ja3_ua_facts, _classify_ja3

p = Path(r"C:\Users\a.grigoryev\Downloads\FIRST-2015_Hands-on_Network_Forensics_PCAP\2015-03-17\snort.log.1426550408")
s = CaptureState()
_extract(p, s, Config())

# Все уникальные JA3 в файле
ja3s = {}
for k, f in s.flows.items():
    if f.ja3:
        ja3s[f.ja3] = ja3s.get(f.ja3, 0) + 1
print(f"Unique JA3 in file: {len(ja3s)}")
for h, c in sorted(ja3s.items(), key=lambda x: -x[1])[:10]:
    print(f"  {h}  x{c}  family={_classify_ja3(h, Config())}")

facts = extract_ja3_ua_facts(s, Config())
print(f"\nExtracted facts: {len(facts)}")
print(f"  uses_ja3: {sum(1 for f in facts if f.predicate == 'uses_ja3')}")
print(f"  uses_ua:  {sum(1 for f in facts if f.predicate == 'uses_ua')}")