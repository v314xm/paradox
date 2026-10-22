# tools/fix_01_stix_deterministic.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "01-stix-deterministic"
TITLE = "STIX: детерминированные ID + valid_from/valid_until"
REL = "paradox_gui/views/export_view.py"

_HELPER_OLD = '''def _is_private_ip(ip_str: str) -> bool:
    from paradox.net_utils import is_private_ip
    return is_private_ip(ip_str)

def _extract_stix_iocs(findings: list) -> list[dict]:
'''

_HELPER_NEW = '''def _is_private_ip(ip_str: str) -> bool:
    from paradox.net_utils import is_private_ip
    return is_private_ip(ip_str)


# Fixed namespace for deterministic STIX indicator/bundle IDs.
_STIX_NS = uuid.UUID("b7e0c8d4-1a2f-4c5e-9f0a-3b4c5d6e7f80")


def _ts_to_iso(ts) -> str | None:
    """Unix timestamp -> ISO-8601 (UTC). None if missing/invalid."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=UTC).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def _stix_indicator_id(ioc_type: str, ioc: str) -> str:
    """Deterministic indicator UUIDv5 from (ioc_type, ioc)."""
    return f"indicator--{uuid.uuid5(_STIX_NS, f'{ioc_type}|{ioc}')}"


def _extract_stix_iocs(findings: list) -> list[dict]:
'''

_BODY_OLD = '''def _extract_stix_iocs(findings: list) -> list[dict]:
    indicators = []
    seen_values = set()

    for f in findings:
        for ip_field in ("src_ip", "dst_ip"):
            ip = f.get(ip_field)
            if ip and not _is_private_ip(ip) and ip not in seen_values:
                seen_values.add(ip)
                indicators.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": datetime.now(UTC).isoformat(),
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now(UTC).isoformat(),
                    "name": "External IP",
                    "description": f"Найден в детекторе: {f.get('type')}"
                })

        val = str(f.get("value", ""))
        domain_match = re.search(
            r'\\b((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,})\\b', val,
        )
        if domain_match:
            domain = domain_match.group(1)
            if domain not in seen_values:
                seen_values.add(domain)
                indicators.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": datetime.now(UTC).isoformat(),
                    "pattern": f"[domain-name:value = '{domain}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now(UTC).isoformat(),
                    "name": "Domain",
                    "description": f"Найден в детекторе: {f.get('type')}"
                })

    return indicators
'''

_BODY_NEW = '''def _extract_stix_iocs(findings: list) -> list[dict]:
    """Extract IOCs from findings as STIX 2.1 indicators."""
    indicators: list[dict] = []
    seen_values: set[str] = set()

    def _emit(ioc_type: str, ioc: str, pattern: str, name: str,
              finding_type: str, first: str, last: str) -> None:
        if ioc in seen_values:
            return
        seen_values.add(ioc)
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_indicator_id(ioc_type, ioc),
            "created": first,
            "modified": first,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": first,
            "valid_until": last,
            "name": name,
            "description": f"Найден в детекторе: {finding_type}",
        })

    for f in findings:
        ftype = f.get("type", "?")
        first = _ts_to_iso(f.get("first_seen")) or datetime.now(UTC).isoformat()
        last = _ts_to_iso(f.get("last_seen")) or first

        for ip_field in ("src_ip", "dst_ip"):
            ip = f.get(ip_field)
            if ip and not _is_private_ip(ip):
                _emit(
                    "ipv4", ip,
                    f"[ipv4-addr:value = '{ip}']",
                    "External IP", ftype, first, last,
                )

        val = str(f.get("value", ""))
        domain_match = re.search(
            r'\\b((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,})\\b', val,
        )
        if domain_match:
            domain = domain_match.group(1)
            _emit(
                "domain", domain,
                f"[domain-name:value = '{domain}']",
                "Domain", ftype, first, last,
            )

    return indicators
'''

_BUNDLE_OLD = '''    def _generate_stix(self) -> str:
        indicators = _extract_stix_iocs(self._report.get("findings", []))
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": indicators
        }
        return json.dumps(bundle, indent=4, ensure_ascii=False)
'''

_BUNDLE_NEW = '''    def _generate_stix(self) -> str:
        indicators = _extract_stix_iocs(self._report.get("findings", []))
        ids_key = "bundle|" + "|".join(
            sorted(ind["id"] for ind in indicators)
        )
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid5(_STIX_NS, ids_key)}",
            "objects": indicators,
        }
        return json.dumps(bundle, indent=4, ensure_ascii=False)
'''


def apply(root: Path) -> bool:
    changed = False
    for old, new in (
        (_HELPER_OLD, _HELPER_NEW),
        (_BODY_OLD,   _BODY_NEW),
        (_BUNDLE_OLD, _BUNDLE_NEW),
    ):
        if patch(root, REL, old, new, required=False):
            changed = True

    if not fix_utils.DRY_RUN:
        text = (root / REL).read_text(encoding="utf-8")
        if "_STIX_NS" not in text or "_stix_indicator_id" not in text:
            raise FixError(
                f"{REL}: не удалось применить — структура не совпадает с ожидаемой"
            )
    return changed
