"""
STIX 2.1 bundle из findings.

Живёт в ядре, а не в GUI: экспорт нужен и headless (CLI `--stix`),
и в графической вкладке «Экспорт» — логика должна быть одна.

Что попадает в bundle:
  - внешние IP из src_ip / dst_ip findings;
  - домены из value, evidence.host(s), unique_destinations.

Внутренние (private) IP не экспортируются: threat-sharing ими
делиться бессмысленно, они есть у каждого.

ID детерминированы (UUIDv5 от типа и значения): повторный прогон
того же pcap даёт тот же bundle, поэтому diff отчётов не шумит.
"""
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from paradox.i18n import L
from paradox.net_utils import is_private_ip

# Фиксированный namespace для indicator/bundle ID.
STIX_NAMESPACE = uuid.UUID("b7e0c8d4-1a2f-4c5e-9f0a-3b4c5d6e7f80")

_DOMAIN_RE = re.compile(r"\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b")


def ts_to_iso(ts) -> str | None:
    """Unix timestamp -> ISO-8601 (UTC). None если значения нет."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=UTC).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def indicator_id(ioc_type: str, ioc: str) -> str:
    """Детерминированный UUIDv5 для indicator."""
    return f"indicator--{uuid.uuid5(STIX_NAMESPACE, f'{ioc_type}|{ioc}')}"


def _iter_evidence_hosts(finding: dict):
    evidence = finding.get("evidence") or {}
    if not isinstance(evidence, dict):
        return
    host = evidence.get("host")
    if isinstance(host, str):
        yield host
    for field in ("hosts", "unique_destinations"):
        values = evidence.get(field)
        if isinstance(values, (list, tuple)):
            for value in values:
                if isinstance(value, str):
                    yield value


def _iter_domains(finding: dict):
    """Домены из value и из evidence-полей с хостами."""
    value = str(finding.get("value", ""))
    match = _DOMAIN_RE.search(value)
    if match:
        yield match.group(1)
    for host in _iter_evidence_hosts(finding):
        host = host.strip().lower()
        if _DOMAIN_RE.fullmatch(host):
            yield host


def extract_iocs(findings: list) -> list[dict]:
    """Собрать STIX-индикаторы из findings без дублей."""
    indicators: list[dict] = []
    seen: set[str] = set()

    def emit(
        ioc_type: str,
        ioc: str,
        pattern: str,
        name: str,
        finding_type: str,
        first: str,
        last: str,
    ) -> None:
        key = f"{ioc_type}|{ioc}"
        if key in seen:
            return
        seen.add(key)
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id(ioc_type, ioc),
            "created": first,
            "modified": first,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": first,
            "valid_until": last,
            "name": name,
            "description": L(
                f"Найден в детекторе: {finding_type}",
                f"Found by detector: {finding_type}",
            ),
        })

    now_iso = datetime.now(UTC).isoformat()
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        ftype = finding.get("type", "?")
        first = ts_to_iso(finding.get("first_seen")) or now_iso
        last = ts_to_iso(finding.get("last_seen")) or first

        for field in ("src_ip", "dst_ip"):
            ip = finding.get(field)
            if ip and not is_private_ip(str(ip)):
                emit(
                    "ipv4", str(ip),
                    f"[ipv4-addr:value = '{ip}']",
                    "External IP", ftype, first, last,
                )

        for domain in _iter_domains(finding):
            emit(
                "domain", domain,
                f"[domain-name:value = '{domain}']",
                "Domain", ftype, first, last,
            )

    return indicators


def build_stix_bundle(report: dict) -> dict:
    """STIX 2.1 bundle со всеми индикаторами отчёта."""
    indicators = extract_iocs(report.get("findings", []))
    ids_key = "bundle|" + "|".join(sorted(ind["id"] for ind in indicators))
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(STIX_NAMESPACE, ids_key)}",
        "objects": indicators,
    }


def render_stix_json(report: dict) -> str:
    """bundle -> JSON-строка (UTF-8, с отступами)."""
    return json.dumps(
        build_stix_bundle(report), indent=4, ensure_ascii=False,
    )


def write_stix(report: dict, path: Path) -> Path:
    path = Path(path)
    path.write_text(render_stix_json(report), encoding="utf-8")
    return path
