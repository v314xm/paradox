"""
IOC reporter: экспорт индикаторов компромисса для EDR/SIEM.

Собирает домены, IP, sha256 и URL из готового dict-отчёта
(выход run_pipeline) и пишет пять файлов:

  iocs.txt        — построчно, для grep/copy-paste
  iocs.csv        — таблица, для Excel/LibreOffice
  iocs.json       — структура, для автоматизации
  suricata.rules  — правила IDS для high-severity IOC
  queries.txt     — KQL (Sentinel/Defender) + Splunk

Никаких внешних API. Источник — то, что уже в отчёте.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
from pathlib import Path

# Типы findings, из которых достаём домены.
_DOMAIN_FINDING_TYPES = frozenset({
    "dga_domain",
    "cloud_tunnel",
    "cloud_tunnel_domain",
    "ip_check_service",
    "typosquatting",
    "sni_without_dns",
})

# Типы findings, из которых достаём IP (dst).
_IP_FINDING_TYPES = frozenset({
    "suspicious_port",
    "brute_force",
    "ftp_brute_force",
    "ssh_brute_force",
    "large_transfer",
    "smtp_spam",
    "ja3_malware",
    "beaconing",
    "lateral_movement",
    "reverse_asymmetry",
})

# Приоритет severity для IOC.
_SEVERITY_RANK = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


def _sev_ge(sev: str, threshold: str) -> bool:
    """severity >= threshold."""
    return _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK.get(threshold, 0)


def _upsert_ioc(
    store: dict,
    key: str,
    new_entry: dict,
    sev_rank: dict,
) -> None:
    """
    Добавить/обновить запись в store с max-severity.

    Если ключ уже есть — повышаем severity до максимальной.
    Это правильнее setdefault: один домен может быть найден
    разными детекторами с разной уверенностью.
    """
    existing = store.get(key)
    if existing is None:
        store[key] = new_entry
        return
    old_rank = sev_rank.get(existing.get("severity", "info"), 0)
    new_rank = sev_rank.get(new_entry.get("severity", "info"), 0)
    if new_rank > old_rank:
        existing["severity"] = new_entry["severity"]
        existing["source"] = new_entry["source"]


def _looks_like_ip(s: str) -> bool:
    """Проверка IPv4/IPv6 через ipaddress."""
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _strip_port(value: str) -> str:
    """'203.0.113.66:4444' → '203.0.113.66'."""
    if ":" in value and value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


def build_ioc_report(report: dict) -> dict:
    """
    Собрать IOC из dict-отчёта.

    Возвращает:
      {
        "domains": [{"value", "severity", "source"}],
        "ips":     [{"value", "severity", "source"}],
        "sha256":  [{"value", "source"}],
        "urls":    [{"value", "source"}],
      }
    Дедуплицировано по value, severity — максимальная из встреченных.
    """
    domains: dict[str, dict] = {}
    ips: dict[str, dict] = {}
    sha256: dict[str, dict] = {}
    urls: dict[str, dict] = {}

    findings = report.get("findings") or []
    for f in findings:
        ftype = f.get("type", "")
        value = f.get("value") or ""
        sev = f.get("severity", "medium")

        if ftype in _DOMAIN_FINDING_TYPES and value:
            _upsert_ioc(
                domains, value,
                {"value": value, "severity": sev, "source": ftype},
                _SEVERITY_RANK,
            )

        elif ftype in _IP_FINDING_TYPES:
            # dst_ip — самый вероятный индикатор.
            ip = f.get("dst_ip") or _strip_port(value)
            if ip and _looks_like_ip(ip):
                _upsert_ioc(
                    ips, ip,
                    {"value": ip, "severity": sev, "source": ftype},
                    _SEVERITY_RANK,
                )

        elif ftype == "vulnerable_path" and value:
            # value = URI, вытащим полный URL если есть host.
            ev = f.get("evidence") or {}
            host = (ev.get("hosts") or [None])[0] if ev.get("hosts") else None
            if host and value.startswith("/"):
                url = f"http://{host}{value}"
                _upsert_ioc(
                    urls, url,
                    {"value": url, "severity": sev, "source": ftype},
                    _SEVERITY_RANK,
                )

    # sha256 из carved_files.
    for cf in (report.get("carved_files") or {}).get("files", []) or []:
        sha = cf.get("sha256")
        if sha and len(sha) == 64:
            sha256.setdefault(sha, {
                "value": sha,
                "source": cf.get("uri") or "carved",
            })

    def _sort(items: dict) -> list[dict]:
        return sorted(
            items.values(),
            key=lambda x: (-_SEVERITY_RANK.get(x.get("severity", "info"), 0),
                           x["value"]),
        )

    return {
        "domains": _sort(domains),
        "ips":     _sort(ips),
        "sha256":  sorted(sha256.values(), key=lambda x: x["value"]),
        "urls":    _sort(urls),
    }


def render_iocs_txt(ioc: dict) -> str:
    """Построчный текстовый формат."""
    lines: list[str] = []
    if ioc["domains"]:
        lines.append("# Domains")
        for d in ioc["domains"]:
            lines.append(d["value"])
        lines.append("")
    if ioc["ips"]:
        lines.append("# IPs")
        for i in ioc["ips"]:
            lines.append(i["value"])
        lines.append("")
    if ioc["urls"]:
        lines.append("# URLs")
        for u in ioc["urls"]:
            lines.append(u["value"])
        lines.append("")
    if ioc["sha256"]:
        lines.append("# SHA256")
        for s in ioc["sha256"]:
            lines.append(s["value"])
        lines.append("")
    return "\n".join(lines)


def render_iocs_csv(ioc: dict) -> str:
    """CSV: type,value,severity,source."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "severity", "source"])
    for d in ioc["domains"]:
        w.writerow(["domain", d["value"],
                    d.get("severity", ""), d.get("source", "")])
    for i in ioc["ips"]:
        w.writerow(["ip", i["value"],
                    i.get("severity", ""), i.get("source", "")])
    for u in ioc["urls"]:
        w.writerow(["url", u["value"],
                    u.get("severity", ""), u.get("source", "")])
    for s in ioc["sha256"]:
        w.writerow(["sha256", s["value"], "", s.get("source", "")])
    return buf.getvalue()


def render_iocs_json(ioc: dict) -> str:
    """Структурированный JSON."""
    return json.dumps(ioc, ensure_ascii=False, indent=2, sort_keys=True)


def render_suricata_rules(ioc: dict) -> str:
    """
    Suricata-правила для домен/IP с severity >= high.

    SID с базой 9000000 — не пересекается с публичными правилами.
    """
    lines: list[str] = [
        "# Paradox generated rules",
        "# SID base 9000000 — local use",
        "",
    ]
    sid = 9000000

    for d in ioc["domains"]:
        if not _sev_ge(d.get("severity", "medium"), "high"):
            continue
        sid += 1
        val = d["value"]
        lines.append(
            f'alert dns $HOME_NET any -> any any '
            f'(msg:"Paradox: malicious domain {val}"; '
            f'dns_query; content:"{val}"; nocase; '
            f'sid:{sid}; rev:1;)'
        )

    for i in ioc["ips"]:
        if not _sev_ge(i.get("severity", "medium"), "high"):
            continue
        sid += 1
        val = i["value"]
        lines.append(
            f'alert ip $HOME_NET any -> {val} any '
            f'(msg:"Paradox: suspicious IP {val}"; '
            f'sid:{sid}; rev:1;)'
        )

    lines.append("")
    return "\n".join(lines)


def render_queries(ioc: dict) -> str:
    """
    KQL (Sentinel/Defender) + Splunk-запросы.

    Аналитик копирует в EDR/SIEM, получает совпадения.
    """
    parts: list[str] = []

    doms = [d["value"] for d in ioc["domains"]]
    ips = [i["value"] for i in ioc["ips"]]
    shas = [s["value"] for s in ioc["sha256"]]

    parts.append("# KQL — Microsoft Sentinel / Defender")
    parts.append("")
    if doms:
        doms_list = ", ".join(f'"{d}"' for d in doms)
        parts.append("# Domains")
        parts.append("DeviceNetworkEvents")
        parts.append(f"| where RemoteUrl in ({doms_list})")
        parts.append("")
    if ips:
        ips_list = ", ".join(f'"{i}"' for i in ips)
        parts.append("# IPs")
        parts.append("DeviceNetworkEvents")
        parts.append(f"| where RemoteIP in ({ips_list})")
        parts.append("")
    if shas:
        shas_list = ", ".join(f'"{s}"' for s in shas)
        parts.append("# SHA256 — поиск запуска файлов")
        parts.append("DeviceProcessEvents")
        parts.append(f"| where SHA256 in ({shas_list})")
        parts.append("")

    parts.append("# Splunk SPL")
    parts.append("")
    if doms:
        doms_or = " OR ".join(f'query="{d}"' for d in doms)
        parts.append("# Domains")
        parts.append(f'index=* ({doms_or})')
        parts.append("")
    if ips:
        ips_or = " OR ".join(f'dest="{i}"' for i in ips)
        parts.append("# IPs")
        parts.append(f'index=* ({ips_or})')
        parts.append("")
    if shas:
        shas_or = " OR ".join(f'sha256="{s}"' for s in shas)
        parts.append("# SHA256")
        parts.append(f'index=* ({shas_or})')
        parts.append("")

    return "\n".join(parts)


def write_ioc_files(ioc: dict, output_dir: Path) -> dict[str, Path]:
    """
    Записать пять файлов в output_dir.

    Возвращает {формат: путь}. Если пусто — пустой dict.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    has_any = any(ioc[k] for k in ("domains", "ips", "sha256", "urls"))
    if not has_any:
        return {}

    written: dict[str, Path] = {}
    mapping = {
        "txt": ("iocs.txt", render_iocs_txt),
        "csv": ("iocs.csv", render_iocs_csv),
        "json": ("iocs.json", render_iocs_json),
        "suricata": ("suricata.rules", render_suricata_rules),
        "queries": ("queries.txt", render_queries),
    }
    for fmt, (name, renderer) in mapping.items():
        content = renderer(ioc)
        if not content.strip():
            continue
        p = output_dir / name
        p.write_text(content, encoding="utf-8")
        written[fmt] = p
    return written
