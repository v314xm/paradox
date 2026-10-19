"""Counterfactual (what-if) анализ.

Позволяет аналитику исключить шумные IP-адреса или домены и посмотреть,
какие находки (findings) останутся.
"""
from __future__ import annotations


def evaluate_what_if(
    report: dict,
    exclude_ips: list[str] | None = None,
    exclude_domains: list[str] | None = None,
) -> dict:
    """Оценить, что произойдет, если исключить указанные IP и домены.

    Возвращает словарь:
      - original_count: сколько было находок
      - removed_count: сколько отфильтровано
      - remaining_count: сколько осталось
      - removed_findings: отфильтрованные находки
      - remaining_findings: оставшиеся находки
      - criteria: примененные фильтры
    """
    exclude_ips = set(exclude_ips or [])
    exclude_domains = set(exclude_domains or [])

    findings = report.get("findings", [])
    if not findings:
        return {
            "original_count": 0,
            "removed_count": 0,
            "remaining_count": 0,
            "removed_findings": [],
            "remaining_findings": [],
            "criteria": {
                "exclude_ips": list(exclude_ips),
                "exclude_domains": list(exclude_domains),
            }
        }

    removed = []
    remaining = []

    for f in findings:
        is_excluded = False

        # 1. Проверяем IP (src_ip / dst_ip)
        if f.get("src_ip") in exclude_ips or f.get("dst_ip") in exclude_ips:
            is_excluded = True

        # 2. Проверяем домен (в поле value или в evidence)
        val = str(f.get("value", ""))
        if any(dom in val for dom in exclude_domains):
            is_excluded = True

        ev = f.get("evidence", {})
        if isinstance(ev, dict):
            ev_domain = str(ev.get("domain", "")) or str(ev.get("sni", ""))
            if any(dom in ev_domain for dom in exclude_domains):
                is_excluded = True

        if is_excluded:
            removed.append(f)
        else:
            remaining.append(f)

    return {
        "original_count": len(findings),
        "removed_count": len(removed),
        "remaining_count": len(remaining),
        "removed_findings": removed,
        "remaining_findings": remaining,
        "criteria": {
            "exclude_ips": list(exclude_ips),
            "exclude_domains": list(exclude_domains),
        }
    }
