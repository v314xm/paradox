"""Fix #29: ip_check_service.last_seen = first_seen из-за _touch(ts=...).

fix_28 добавил timestamps в ip_check_service, но передавал только
ts=flow.first_ts. _touch писал это значение и в h["first"], и в
h["last"] — в результате last_seen всегда равен first_seen.

Фикс: _touch принимает first_ts и last_ts отдельно. Для DNS-источника
пока ts нет (нужен отдельный fix для dns_query_ts_by_name), поэтому
DNS-вызовы остаются без timestamps — для них timeline строится по
SNI/Host/direct_ip, которые есть в flow.
"""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError, assert_applied

FIX_ID = "29-ipcheck-last-ts"
TITLE = "ip_check_service: last_seen != first_seen"

REL = "paradox/detectors/ip_check_service.py"

_OLD_TOUCH = """        def _touch(value: str, source: str, extra: dict | None = None,
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

_NEW_TOUCH = """        def _touch(value: str, source: str, extra: dict | None = None,
                   first_ts: float | None = None,
                   last_ts: float | None = None) -> None:
            h = hits.setdefault(value, {
                "sources": set(), "extra": {},
                "first": None, "last": None,
            })
            h["sources"].add(source)
            if extra:
                h["extra"].update(extra)
            if first_ts is not None:
                if h["first"] is None or first_ts < h["first"]:
                    h["first"] = first_ts
            if last_ts is not None:
                if h["last"] is None or last_ts > h["last"]:
                    h["last"] = last_ts"""

_OLD_CALLS = """        for key, flow in state.flows.items():
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

_NEW_CALLS = """        for key, flow in state.flows.items():
            if flow.sni:
                sni = flow.sni.lower().strip(".")
                if sni in services:
                    _touch(
                        sni, "sni",
                        {"flow": f"{key.src_ip} -> {key.dst_ip}"},
                        first_ts=flow.first_ts,
                        last_ts=flow.last_ts,
                    )

            if flow.http_host:
                host = flow.http_host.split(":", 1)[0].lower().strip(".")
                if host in services:
                    _touch(
                        host, "http_host",
                        {"flow": f"{key.src_ip} -> {key.dst_ip}"},
                        first_ts=flow.first_ts,
                        last_ts=flow.last_ts,
                    )

            # direct IP — каноническое имя сервиса как value,
            # чтобы finding слился с DNS/SNI-находками
            service_name = service_ips.get(key.dst_ip)
            if service_name:
                _touch(
                    service_name, "direct_ip",
                    {"flow": f"{key.src_ip} -> {key.dst_ip}"},
                    first_ts=flow.first_ts,
                    last_ts=flow.last_ts,
                )"""


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL, _OLD_TOUCH, _NEW_TOUCH, required=False):
        changed = True
    if patch(root, REL, _OLD_CALLS, _NEW_CALLS, required=False):
        changed = True
    assert_applied(root, REL, "last_ts=flow.last_ts")
    assert_applied(root, REL, "first_ts=flow.first_ts")
    return changed