"""Проверка run_multi_pipeline на двух половинках pcap."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from paradox.config import Config
from paradox.pipeline import run_multi_pipeline


def main():
    pcaps = sorted(ROOT.glob("*.pcap"))
    if len(pcaps) < 2:
        print(f"Нужно 2 pcap. Найдено: {len(pcaps)}")
        return 1

    pcaps = pcaps[:2]
    print("Files:", [p.name for p in pcaps])
    cfg = Config(tcp_reassembly_enabled=False)

    print("\nrun_multi_pipeline ...")
    report = run_multi_pipeline(pcaps, cfg)

    s = report["summary"]
    print(f"  packets:        {s['packets']}")
    print(f"  flows:          {s['flows']}")
    print(f"  findings:       {s['findings']}")
    print(f"  contradictions: {s['contradictions']}")
    print(f"  provenance:     {report['provenance']['pcap_path']}")
    print(f"  merged_files:   {report['provenance'].get('merged_files')}")

    ag = report.get("attack_graph", {})
    print(f"  attack_graph:   nodes={len(ag.get('nodes', []))} "
          f"edges={len(ag.get('edges', []))} paths={len(ag.get('paths', []))}")

    assert s["packets"] > 0
    assert report["provenance"]["pcap_path"].startswith("merged:")
    assert len(report["provenance"].get("merged_files", [])) == 2

    print("\n[OK] run_multi_pipeline works end-to-end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
