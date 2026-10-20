"""Разрезать pcap на две половины для теста multi-pcap."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

from scapy.all import rdpcap, wrpcap


def main():
    pcaps = sorted(ROOT.glob("*.pcap"))
    if not pcaps:
        print("Нет .pcap в корне")
        return 1

    src = pcaps[0]
    print(f"Source: {src.name}")

    packets = rdpcap(str(src))
    total = len(packets)
    half = total // 2
    print(f"Total packets: {total}, split at {half}")

    out1 = ROOT / f"{src.stem}_part1.pcap"
    out2 = ROOT / f"{src.stem}_part2.pcap"

    wrpcap(str(out1), packets[:half])
    wrpcap(str(out2), packets[half:])
    print(f"  {out1.name}: {half} packets")
    print(f"  {out2.name}: {total - half} packets")

    print("\n[OK] split done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
