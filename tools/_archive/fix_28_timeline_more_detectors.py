"""Fix #28: first_seen/last_seen в smtp_spam, ip_check_service, nxdomain_burst.

Все три детектора имеют данные для timestamps, но не читают их:
- smtp_spam:        flow.first_ts/last_ts на портах 25/465/587
- ip_check_service: flow.first_ts где найден сервис
- nxdomain_burst:   state.dns_nxdomain_ts_by_src (уже собирается)

После фикса все три видны в timeline и kill-chain фазах.
"""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError, assert_applied

FIX_ID = "28-timeline-more-detectors"
TITLE = "timeline: first_seen/last_seen в smtp_spam/ip_check/nxdomain_burst"


# ======================= smtp_spam =====================================
REL_SMTP = "paradox/detectors/smtp_spam.py"

_OLD_SMTP = """            # v1.1: dst из flows SMTP-портов.
            dst_counts = {}
            for key in state.flows:
                if key.src_ip == src_ip and key.dst_port in (25, 465, 587):
                    dst_counts[key.dst_ip] = dst_counts.get(key.dst_ip, 0) + 1
            top_dsts = sorted(
                ({"ip": ip, "count": c} for ip, c in dst_counts.items()),
                key=lambda d: -d["count"],
            )[:5]"""

_NEW_SMTP = """            # v1.1: dst из flows SMTP-портов + timestamps.
            dst_counts = {}
            first_seen: float | None = None
            last_seen: float | None = None
            for key, flow in state.flows.items():
                if key.src_ip == src_ip and key.dst_port in (25, 465, 587):
                    dst_counts[key.dst_ip] = dst_counts.get(key.dst_ip, 0) + 1
                    if flow.first_ts is not None:
                        if first_seen is None or flow.first_ts < first_seen:
                            first_seen = flow.first_ts
                    if flow.last_ts is not None:
                        if last_seen is None or flow.last_ts > last_seen:
                            last_seen = flow.last_ts
            top_dsts = sorted(
                ({"ip": ip, "count": c} for ip, c in dst_counts.items()),
                key=lambda d: -d["count"],
            )[:5]"""

_OLD_SMTP_FINDING = """            findings.append(Finding(
                type="smtp_spam",
                value=f"{src_ip} -> {count} recipients",
                confidence=confidence,
                evidence=evidence,
            ))"""

_NEW_SMTP_FINDING = """            findings.append(Finding(
                type="smtp_spam",
                value=f"{src_ip} -> {count} recipients",
                confidence=confidence,
                evidence=evidence,
                first_seen=first_seen,
                last_seen=last_seen,
            ))"""


# ======================= ip_check_service ==============================
REL_IPCHECK = "paradox/detectors/ip_check_service.py"

_OLD_IPCHECK_TOUCH = """        # value (имя сервиса) -> {sources: set, extra: dict}
        hits: dict[str, dict] = {}

        def _touch(value: str, source: str, extra: dict | None = None) -> None:
            h = hits.setdefault(value, {"sources": set(), "extra": {}})
            h["sources"].add(source)
            if extra:
                h["extra"].update(extra)"""

_NEW_IPCHECK_TOUCH = """        # value (имя сервиса) -> {sources: set, extra: dict, first, last}
        hits: dict[str, dict] = {}

        def _touch(value: str, source: str, extra: dict | None = None,
                   ts: float | None = None) -> None:
            h = hits.setdefault(value, {
                "sources": set(), "extra": {},
                "first": None, "last": None,
            })
            h["sources"].add(source)
            if extra:
                h["extra"].update(extra)
            if ts is not None:
                if h["first"] is None or ts < h["first"]:
                    h["first"] = ts
                if h["last"] is None or ts > h["last"]:
                    h["last"] = ts"""

_OLD_IPCHECK_FLOW = """        for key, flow in state.flows.items():
            if flow.sni:
                sni = flow.sni.lower().strip(".")
                if sni in services:
                    _touch(sni, "sni",
                           {"flow": f"{key.src_ip} -> {key.dst_ip}"})

            if flow.http_host:
                host = flow.http_host.split(":", 1)[0].lower().strip(".")
                if host in services:
                    _touch(host, "http_host",
                           {"flow": f"{key.src_ip} -> {key.dst_ip}"})

            # direct IP — используем каноническое имя сервиса как value,
            # чтобы finding слился с DNS/SNI-находками
            service_name = service_ips.get(key.dst_ip)
            if service_name:
                _touch(service_name, "direct_ip",
                       {"flow": f"{key.src_ip} -> {key.dst_ip}"})"""

_NEW_IPCHECK_FLOW = """        for key, flow in state.flows.items():
            if flow.sni:
                sni = flow.sni.lower().strip(".")
                if sni in services:
                    _touch(sni, "sni",
                           {"flow": f"{key.src_ip} -> {key.dst_ip}"},
                           ts=flow.first_ts)

            if flow.http_host:
                host = flow.http_host.split(":", 1)[0].lower().strip(".")
                if host in services:
                    _touch(host, "http_host",
                           {"flow": f"{key.src_ip} -> {key.dst_ip}"},
                           ts=flow.first_ts)

            # direct IP — каноническое имя сервиса как value,
            # чтобы finding слился с DNS/SNI-находками
            service_name = service_ips.get(key.dst_ip)
            if service_name:
                _touch(service_name, "direct_ip",
                       {"flow": f"{key.src_ip} -> {key.dst_ip}"},
                       ts=flow.first_ts)"""

_OLD_IPCHECK_FINDING = """        findings: list[Finding] = []
        for value, h in hits.items():
            findings.append(Finding(
                type="ip_check_service",
                value=value,
                confidence=0.7,
                evidence={
                    "sources": sorted(h["sources"]),
                    **h["extra"],
                },
            ))"""

_NEW_IPCHECK_FINDING = """        findings: list[Finding] = []
        for value, h in hits.items():
            findings.append(Finding(
                type="ip_check_service",
                value=value,
                confidence=0.7,
                evidence={
                    "sources": sorted(h["sources"]),
                    **h["extra"],
                },
                first_seen=h["first"],
                last_seen=h["last"],
            ))"""


# ======================= nxdomain_burst ================================
REL_NXDOMAIN = "paradox/detectors/nxdomain_burst.py"

_OLD_NXDOMAIN = """            findings.append(Finding(
                type="nxdomain_burst",
                value=src_ip,
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "nxdomain_count": total,
                    "max_in_window": max_win,
                    "window_sec": window,
                    "threshold": threshold,
                    "windowed": windowed,
                    "ratio": round(ratio, 3),
                    "total_dns_queries": total_dns,
                },
            ))"""

_NEW_NXDOMAIN = """            # timestamps для timeline
            first_seen: float | None = None
            last_seen: float | None = None
            if ts_list:
                first_seen = min(ts_list)
                last_seen = max(ts_list)

            findings.append(Finding(
                type="nxdomain_burst",
                value=src_ip,
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "nxdomain_count": total,
                    "max_in_window": max_win,
                    "window_sec": window,
                    "threshold": threshold,
                    "windowed": windowed,
                    "ratio": round(ratio, 3),
                    "total_dns_queries": total_dns,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            ))"""


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_SMTP, _OLD_SMTP, _NEW_SMTP, required=False):
        changed = True
    if patch(root, REL_SMTP, _OLD_SMTP_FINDING, _NEW_SMTP_FINDING, required=False):
        changed = True
    if patch(root, REL_IPCHECK, _OLD_IPCHECK_TOUCH, _NEW_IPCHECK_TOUCH, required=False):
        changed = True
    if patch(root, REL_IPCHECK, _OLD_IPCHECK_FLOW, _NEW_IPCHECK_FLOW, required=False):
        changed = True
    if patch(root, REL_IPCHECK, _OLD_IPCHECK_FINDING, _NEW_IPCHECK_FINDING, required=False):
        changed = True
    if patch(root, REL_NXDOMAIN, _OLD_NXDOMAIN, _NEW_NXDOMAIN, required=False):
        changed = True

    assert_applied(root, REL_SMTP, "first_seen=first_seen")
    assert_applied(root, REL_IPCHECK, 'h["first"]')
    assert_applied(root, REL_NXDOMAIN, "first_seen=first_seen")
    return changed