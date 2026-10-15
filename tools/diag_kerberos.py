"""Детальная диагностика Kerberos-парсера."""
from scapy.utils import RawPcapReader

from pcap_triage.kerberos_parse import parse_kerberos, _read_tlv, TAG_APPLICATION
from pcap_triage.parsers import parse_packet

PCAP = r'C:\Users\a.grigoryev\Downloads\2025-06-13-traffic-analysis-exercise.pcap\2025-06-13-traffic-analysis-exercise.pcap'

reader = RawPcapReader(PCAP)

total = 0
first_byte_hist: dict[int, int] = {}
parse_result = {"None": 0, "empty": 0, "with_data": 0}
shown = 0

for raw, meta in reader:
    ts = meta.sec + meta.usec / 1_000_000
    record = parse_packet(raw, ts)

    if record.proto not in ("udp", "tcp"):
        continue
    if record.src_port != 88 and record.dst_port != 88:
        continue
    if not record.payload:
        continue

    total += 1
    payload = record.payload
    first = payload[0] if payload else -1
    first_byte_hist[first] = first_byte_hist.get(first, 0) + 1

    info = parse_kerberos(payload)

    if info is None:
        parse_result["None"] += 1
        # показать первые 3 пакета, которые вернули None
        if shown < 3:
            shown += 1
            print(f"--- pkt {total} (None) ---")
            print(f"  src={record.src_ip}:{record.src_port} "
                  f"dst={record.dst_ip}:{record.dst_port} "
                  f"proto={record.proto} len={len(payload)}")
            print(f"  first 32 bytes: {payload[:32].hex()}")
    else:
        has_data = (info.msg_type is not None or info.cname is not None
                    or info.sname is not None or info.realm is not None
                    or info.crealm is not None)
        if has_data:
            parse_result["with_data"] += 1
            if shown < 10:
                shown += 1
                print(f"--- pkt {total} (data) ---")
                print(f"  type={info.msg_type} cname={info.cname!r} "
                      f"sname={info.sname!r} crealm={info.crealm!r} "
                      f"realm={info.realm!r}")
        else:
            parse_result["empty"] += 1
            if shown < 6:
                shown += 1
                print(f"--- pkt {total} (empty) ---")
                print(f"  src={record.src_ip}:{record.src_port} "
                      f"dst={record.dst_ip}:{record.dst_port} "
                      f"proto={record.proto} len={len(payload)}")
                print(f"  first 32 bytes: {payload[:32].hex()}")

reader.close()

print()
print(f"Kerberos packets: {total}")
print(f"parse_result: {parse_result}")
print()
print("Распределение первого байта (hex):")
for b, c in sorted(first_byte_hist.items()):
    print(f"  0x{b:02x}  ({b}): {c}")