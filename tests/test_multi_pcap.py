"""Проверка слияния pcap вручную (без pipeline).

Это НЕ pytest-файл: здесь нет `def test_*`, а `main()` запускается
руками (`python tests/test_multi_pcap.py`). Маркер ниже — формальность
на случай, если кто-то добавит сюда `test_*`.
"""
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skip(reason="manual integration script, run directly")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from paradox.config import Config
from paradox.models import CaptureState
from paradox.multi_pcap import merge_capture_states
from paradox.pipeline import _detect, _extract


def main():
    # Ищем pcap в корне проекта
    pcaps = sorted(ROOT.glob("*.pcap"))
    if len(pcaps) < 2:
        print(f"Нужно 2 pcap-файла в корне. Найдено: {len(pcaps)}")
        print(f"Положи файлы в {ROOT}")
        return 1

    pcaps = pcaps[:2]
    print("Files:", [p.name for p in pcaps])
    cfg = Config(tcp_reassembly_enabled=False)

    states = []
    for p in pcaps:
        print(f"  Extract: {p.name} ...")
        st = CaptureState()
        _extract(p, st, cfg)
        states.append(st)
        print(f"    packets={st.packet_count} flows={len(st.flows)}")

    print("  Merging ...")
    merged = merge_capture_states(states)

    expected_packets = sum(s.packet_count for s in states)
    print(f"  Merged: packets={merged.packet_count} (expected {expected_packets})")
    print(f"  Merged: flows={len(merged.flows)}")

    if merged.packet_count != expected_packets:
        print("[FAIL] packet count mismatch")
        return 1

    print("  Detect (на слитом state) ...")
    findings = _detect(merged, cfg)
    print(f"  Findings: {len(findings)}")
    for f in findings[:5]:
        print(f"    [{f.severity}] {f.type}: {f.value}")

    print("\n[OK] Multi-pcap merge works!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
