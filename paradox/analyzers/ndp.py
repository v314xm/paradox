"""Агрегатор NDP для отчёта.

Собирает Neighbor Advertisements, Solicitations и Router Advertisements
в единую структуру для сериализации в JSON.
"""
from __future__ import annotations

from paradox.extractors.ndp import extract_ndp


def analyze_ndp(packets) -> dict:
    """Пройтись по пакетам и собрать NDP-статистику.

    Возвращает словарь:
      {
        "total": int,
        "neighbors": [{"ip": str, "mac": str}],
        "routers": [str]
      }
    """
    ndp_records = []
    for pkt in packets:
        ndp = extract_ndp(pkt)
        if ndp:
            ndp_records.append(ndp)

    if not ndp_records:
        return {"total": 0, "neighbors": [], "routers": []}

    neighbors = {}
    routers = set()

    for n in ndp_records:
        if n.kind == "na" and n.target_ip and n.target_mac:
            neighbors[n.target_ip] = n.target_mac
        elif n.kind == "ns" and n.target_ip and n.source_mac:
            if n.target_ip not in neighbors:  # не перезаписываем NA
                neighbors[n.target_ip] = n.source_mac
        elif n.kind == "ra" and n.src_ip:
            routers.add(n.src_ip)

    return {
        "total": len(ndp_records),
        "neighbors": [{"ip": k, "mac": v} for k, v in neighbors.items()],
        "routers": list(routers),
    }
