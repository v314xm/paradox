"""Markdown-отчёт: iocs."""
from __future__ import annotations

from paradox.taxonomy import chain_order_for


def _extract_iocs(findings: list[dict]) -> dict:
    """Простое извлечение IOC из findings."""
    domains: dict[str, list[str]] = {}
    ips: dict[str, list[str]] = {}
    ports: dict[int, list[str]] = {}

    for f in findings:
        ftype = f.get("type", "")
        value = f.get("value", "")

        if ftype in ("dga_domain", "cloud_tunnel_domain",
                     "ip_check_service", "typosquatting",
                     "sni_without_dns"):
            domains.setdefault(value, []).append(ftype)

        elif ftype == "suspicious_port":
            if ":" in value:
                ip, port_s = value.rsplit(":", 1)
                ips.setdefault(ip, []).append(ftype)
                try:
                    ports.setdefault(int(port_s), []).append(ftype)
                except ValueError:
                    pass

        elif ftype == "nxdomain_burst":
            ips.setdefault(value, []).append(ftype)

    return {"domains": domains, "ips": ips, "ports": ports}


def _pick_first_with_role(entities: list[dict], role: str) -> str | None:
    for e in entities:
        if role in e.get("roles", []):
            return e.get("ip")
    return None


def _unique_finding_types(findings: list[dict]) -> list[str]:
    seen: list[str] = []
    for f in findings:
        t = f.get("type")
        if t and t not in seen:
            seen.append(t)
    return seen


def _chain_for(findings: list[dict]) -> list[str]:
    """
    Уникальные типы findings в порядке kill-chain.

    Приоритет — цепочка, а не confidence: аналитик должен видеть
    «скан → RCE → payload → beacon», даже если beacon confidence выше.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for f in findings:
        t = f.get("type")
        if t and t not in seen:
            seen.add(t)
            ordered.append(t)
    return sorted(ordered, key=lambda t: (chain_order_for(t), t))
