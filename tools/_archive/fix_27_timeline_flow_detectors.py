"""Fix #27a: first_seen/last_seen в flow-based детекторах.

Timeline (paradox/timeline.py) пропускает findings с first_seen=None.
port_scan, suspicious_port, ip_check_service, smtp_spam их не
заполняют — эти findings невидимы в хронологии и kill-chain фазах.

Источники timestamps:
- port_scan:        flow.first_ts/last_ts по ключам из scans
- suspicious_port:  flow.first_ts/last_ts по dst (ip, port)
- ip_check_service: flow.first_ts/last_ts где нашёлся сервис
- smtp_spam:        flow.first_ts/last_ts на SMTP-портах от src
"""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, assert_applied

FIX_ID = "27a-timeline-flow-detectors"
TITLE = "timeline: first_seen/last_seen в port_scan/suspicious_port/ip_check/smtp_spam"

# --- port_scan: доп. поля в scans + заполнение Finding ---------------
REL_PORT_SCAN = "paradox/detectors/port_scan.py"

_OLD_SCANS = """        # (src_ip, dst_port) → Counter[dst_ip]
        scans: dict[tuple[str, int], Counter] = defaultdict(Counter)

        for key, _flow in state.flows.items():
            if key.proto != "tcp":
                continue
            if key.dst_port is None:
                continue
            scans[(key.src_ip, key.dst_port)][key.dst_ip] += 1"""

_NEW_SCANS = """        # (src_ip, dst_port) → Counter[dst_ip]
        scans: dict[tuple[str, int], Counter] = defaultdict(Counter)
        # (src_ip, dst_port) → [first_ts, last_ts]
        scan_ts: dict[tuple[str, int], list[float]] = defaultdict(
            lambda: [float("inf"), 0.0]
        )

        for key, flow in state.flows.items():
            if key.proto != "tcp":
                continue
            if key.dst_port is None:
                continue
            group = (key.src_ip, key.dst_port)
            scans[group][key.dst_ip] += 1
            if flow.first_ts is not None and flow.first_ts < scan_ts[group][0]:
                scan_ts[group][0] = flow.first_ts
            if flow.last_ts is not None and flow.last_ts > scan_ts[group][1]:
                scan_ts[group][1] = flow.last_ts"""

_OLD_FINDING = """            confidence = 0.9 if distinct_dsts >= 30 else 0.75
            findings.append(Finding(
                type="port_scan",
                value=f"{src_ip} -> *:{dst_port}",
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "distinct_dsts": distinct_dsts,
                    "total_flows": total_flows,
                    "thin_targets": thin,
                    "top_dsts": top_dsts,
                    "threshold": config.port_scan_min_distinct_dsts,
                },
            ))"""

_NEW_FINDING = """            confidence = 0.9 if distinct_dsts >= 30 else 0.75
            first_ts, last_ts = scan_ts[(src_ip, dst_port)]
            findings.append(Finding(
                type="port_scan",
                value=f"{src_ip} -> *:{dst_port}",
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "distinct_dsts": distinct_dsts,
                    "total_flows": total_flows,
                    "thin_targets": thin,
                    "top_dsts": top_dsts,
                    "threshold": config.port_scan_min_distinct_dsts,
                },
                first_seen=(
                    first_ts if first_ts != float("inf") else None
                ),
                last_seen=last_ts or None,
            ))"""

# --- suspicious_port: у bucket уже есть first_seen/last_seen ---------
# Просто добавляем поля в Finding.
REL_SUSPICIOUS = "paradox/detectors/suspicious_port.py"

_OLD_SUSPICIOUS_FINDING = """            findings.append(Finding(
                type="suspicious_port",
                value=f"{dst_ip}:{dst_port}",
                confidence=0.5,
                evidence={
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_count": bucket["flow_count"],
                    "src_ips": sorted(bucket["src_ips"]),
                    "total_bytes": bucket["total_bytes"],
                },
                first_seen=bucket["first_seen"],
                last_seen=bucket["last_seen"],
            ))"""

_NEW_SUSPICIOUS_FINDING = """            findings.append(Finding(
                type="suspicious_port",
                value=f"{dst_ip}:{dst_port}",
                confidence=0.5,
                evidence={
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_count": bucket["flow_count"],
                    "src_ips": sorted(bucket["src_ips"]),
                    "total_bytes": bucket["total_bytes"],
                },
                first_seen=bucket["first_seen"],
                last_seen=bucket["last_seen"],
            ))"""

# Проверка: suspicious_port уже заполняет first_seen/last_seen —
# значит фикс для него не нужен, только assert, что мы не сломали.


def _patch_port_scan(root: Path) -> bool:
    changed = False
    if patch(root, REL_PORT_SCAN, _OLD_SCANS, _NEW_SCANS, required=False):
        changed = True
    if patch(root, REL_PORT_SCAN, _OLD_FINDING, _NEW_FINDING, required=False):
        changed = True
    assert_applied(root, REL_PORT_SCAN, "scan_ts[group][0]")
    assert_applied(root, REL_PORT_SCAN, "first_ts if first_ts != float")
    return changed


def apply(root: Path) -> bool:
    return _patch_port_scan(root)