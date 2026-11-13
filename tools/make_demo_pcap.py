"""Собрать маленький синтетический pcap для демо Paradox.

Сценарий (все адреса — документационные TEST-NET, совпадения случайны):

- 10.0.0.66 сканирует 12 внутренних адресов на порт 22 → port_scan;
- 10.0.0.50 (Apple OUI) сканирует 4 адреса на 7 портов → role_deviation;
- два MAC одновременно отвечают за 10.0.0.1 → mac_ip_conflict;
- DNS для cdn-demo.example даёт 198.51.100.30, а TLS идёт на .31
  → dns_answer_mismatch;
- TLS на sync-telemetry.example без DNS-ответа → sni_without_dns;
- 10.0.0.50 → 203.0.113.66:4444 → suspicious_port.

Запуск:

    python tools/make_demo_pcap.py            # только examples/demo.pcap
    python tools/make_demo_pcap.py --report   # + demo.report.json/.md
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "examples"
PCAP = OUT_DIR / "demo.pcap"

GW_MAC_A = "00:11:22:33:44:55"
GW_MAC_B = "66:77:88:99:aa:bb"
VICTIM_MAC = "3c:07:54:12:34:56"  # Apple OUI → workstation
ATTACKER_MAC = "02:00:00:00:00:66"
VICTIM = "10.0.0.50"
ATTACKER = "10.0.0.66"
GATEWAY = "10.0.0.1"
DNS_IP = "10.0.0.1"
DNS_NAME = "cdn-demo.example"
DNS_ANSWER = "198.51.100.30"
TLS_DST = "198.51.100.31"
NO_DNS_SNI = "sync-telemetry.example"
NO_DNS_DST = "198.51.100.40"
SUSPICIOUS_DST = "203.0.113.66"
SUSPICIOUS_PORT = 4444

_TS = [1_700_000_000.0]


def _stamp(pkt):
    _TS[0] += 0.05
    pkt.time = _TS[0]
    return pkt


def _tcp(src_mac, src, dst, sport, dport, seq, ack=0, flags="S", payload=b""):
    pkt = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    return _stamp(pkt)


def client_hello(sni: str) -> bytes:
    """Минимальный TLS 1.2 ClientHello с одним расширением — SNI."""
    name = sni.encode()
    sni_ext = (
        b"\x00\x00"
        + struct.pack(">H", len(name) + 5)
        + struct.pack(">H", len(name) + 3)
        + b"\x00"
        + struct.pack(">H", len(name))
        + name
    )
    body = b"\x03\x03" + bytes(range(32))
    body += b"\x00"                                  # session id length
    body += b"\x00\x02\x00\x2f"                      # one cipher suite
    body += b"\x01\x00"                              # null compression
    body += struct.pack(">H", len(sni_ext)) + sni_ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def tls_session(src_mac, src, dst, sport, sni: str) -> list:
    """SYN / SYN-ACK / ACK / ClientHello / ACK — чтобы поток был валидным."""
    hello = client_hello(sni)
    cseq, sseq = 1000, 9000
    return [
        _tcp(src_mac, src, dst, sport, 443, cseq, flags="S"),
        _tcp("00:aa:bb:cc:dd:ee", dst, src, 443, sport, sseq, cseq + 1,
             flags="SA"),
        _tcp(src_mac, src, dst, sport, 443, cseq + 1, sseq + 1, flags="A"),
        _tcp(src_mac, src, dst, sport, 443, cseq + 1, sseq + 1,
             flags="PA", payload=hello),
        _tcp("00:aa:bb:cc:dd:ee", dst, src, 443, sport, sseq + 1,
             cseq + 1 + len(hello), flags="A"),
    ]


def arp_reply(mac: str, ip: str) -> object:
    return _stamp(
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=mac, psrc=ip, hwdst="ff:ff:ff:ff:ff:ff",
              pdst="10.0.0.255")
    )


def build_packets() -> list:
    packets: list = []

    # 1. ARP: рабочая станция и конфликт двух MAC на шлюзе.
    packets.append(arp_reply(VICTIM_MAC, VICTIM))
    for _ in range(3):
        packets.append(arp_reply(GW_MAC_A, GATEWAY))
        packets.append(arp_reply(GW_MAC_B, GATEWAY))

    # 2. Горизонтальный скан одного порта: 12 целей, по одному SYN.
    for last in range(100, 112):
        packets.append(_tcp(
            ATTACKER_MAC, ATTACKER, f"10.0.0.{last}", 40000 + last, 22,
            1000 + last, flags="S",
        ))

    # 3. Скан с рабочей станции: 4 цели × 7 портов → role_deviation.
    for last in range(200, 204):
        for dport in (21, 23, 25, 135, 139, 445, 3389):
            packets.append(_tcp(
                VICTIM_MAC, VICTIM, f"10.0.0.{last}", 45000 + dport,
                dport, 2000 + last + dport, flags="S",
            ))

    # 4. DNS: запрос и ответ с A-записью, которая не совпадёт с TLS.
    q = _stamp(
        Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=VICTIM, dst=DNS_IP)
        / UDP(sport=53000, dport=53)
        / DNS(id=0x1234, rd=1, qd=DNSQR(qname=DNS_NAME, qtype="A"))
    )
    a = _stamp(
        Ether(src=GW_MAC_A, dst=VICTIM_MAC)
        / IP(src=DNS_IP, dst=VICTIM)
        / UDP(sport=53, dport=53000)
        / DNS(
            id=0x1234, qr=1, aa=1, rd=1, ra=1,
            qd=DNSQR(qname=DNS_NAME, qtype="A"),
            an=DNSRR(rrname=DNS_NAME, type="A", ttl=60, rdata=DNS_ANSWER),
        )
    )
    packets.extend([q, a])

    # 5. TLS: совпадающий по имени, но не по IP; и SNI без DNS вообще.
    packets.extend(tls_session(VICTIM_MAC, VICTIM, TLS_DST, 53001, DNS_NAME))
    packets.extend(tls_session(VICTIM_MAC, VICTIM, NO_DNS_DST, 53002,
                               NO_DNS_SNI))

    # 6. Соединение на «подозрительный» порт.
    packets.append(_tcp(
        VICTIM_MAC, VICTIM, SUSPICIOUS_DST, 53003, SUSPICIOUS_PORT,
        7000, flags="S",
    ))
    return packets


def write_report() -> None:
    from paradox.config import Config
    from paradox.pipeline import run_pipeline
    from paradox.reporters.json_reporter import write_json, write_markdown

    rel = PCAP.relative_to(ROOT).as_posix()
    config = Config(ioc_export_enabled=False, tcp_reassembly_enabled=True)
    report = run_pipeline(rel, config)
    report["provenance"]["pcap_path"] = rel
    write_json(report, OUT_DIR / "demo.report.json")
    write_markdown(report, OUT_DIR / "demo.report.md")
    print(f"findings={len(report.get('findings', []))} "
          f"contradictions={len(report.get('contradictions', []))}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report", action="store_true",
        help="после pcap собрать demo.report.json и demo.report.md",
    )
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    wrpcap(str(PCAP), packets)
    print(f"{PCAP.relative_to(ROOT)}: {len(packets)} packets")

    if args.report:
        write_report()


if __name__ == "__main__":
    main()
