"""Анализ истории одного хоста.

Собирает все события (flows, findings) для конкретного IP,
сортирует их по времени и выдает краткую сводку.
"""
from __future__ import annotations


def build_host_story(report: dict, target_ip: str) -> dict:
    """Собрать хронологию событий для указанного IP.

    Возвращает словарь:
      - target_ip: анализируемый IP
      - events: список событий, отсортированный по времени (ts)
      - summary: краткая статистика
    """
    events = []
    ips_contacted = set()

    # 1. Извлекаем потоки
    flows = report.get("flows", {}).get("top_by_bytes", [])
    for flow in flows:
        src = flow.get("src_ip")
        dst = flow.get("dst_ip")

        if src == target_ip or dst == target_ip:
            ts = flow.get("first_ts") or 0
            events.append({
                "type": "flow",
                "ts": ts,
                "data": flow
            })

            if src == target_ip and dst:
                ips_contacted.add(dst)
            elif dst == target_ip and src:
                ips_contacted.add(src)

    # 2. Извлекаем находки
    findings = report.get("findings", [])
    for f in findings:
        if f.get("src_ip") == target_ip or f.get("dst_ip") == target_ip:
            ts = f.get("first_seen") or 0
            events.append({
                "type": "finding",
                "ts": ts,
                "data": f
            })

    # 3. Сортируем по времени
    events.sort(key=lambda x: x["ts"])

    findings_count = sum(1 for e in events if e["type"] == "finding")
    flows_count = sum(1 for e in events if e["type"] == "flow")

    return {
        "target_ip": target_ip,
        "events": events,
        "summary": {
            "total_events": len(events),
            "findings_count": findings_count,
            "flows_count": flows_count,
            "unique_contacts": len(ips_contacted),
        }
    }
