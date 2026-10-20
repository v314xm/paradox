"""Проверка: возвращает ли run_pipeline данные графа атаки."""
from pathlib import Path

from paradox.config import Config
from paradox.pipeline import run_pipeline


def main():
    pcaps = list(Path(".").glob("*.pcap"))
    if not pcaps:
        print("Нет pcap в корне")
        return 1

    pcap = pcaps[0]
    print(f"Прогон: {pcap.name} ...")
    report = run_pipeline(pcap, Config(tcp_reassembly_enabled=False))

    ag = report.get("attack_graph")
    if ag is None:
        print("\n[FAIL] Отчёт не содержит ключа 'attack_graph'.")
        print("Нужно запустить: python tools\\fix_attack_graph_in_run_pipeline.py")
        return 1

    print("\n[OK] Ключ 'attack_graph' есть в отчёте.")
    print(f"  Nodes: {len(ag.get('nodes', []))}")
    print(f"  Edges: {len(ag.get('edges', []))}")
    print(f"  Paths: {len(ag.get('paths', []))}")
    print(f"  Entry: {ag.get('entry_points')}")
    print(f"  Impact: {ag.get('impact_targets')}")

    if len(ag.get('nodes', [])) == 0:
        print("\n[WARN] Граф пуст (0 узлов). Значит build_attack_graph вернул пустой граф.")
        print("Проверь: есть ли в findings src_ip и dst_ip?")

    return 0


if __name__ == "__main__":
    exit(main())
