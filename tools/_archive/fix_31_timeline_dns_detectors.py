"""Fix #31: first_seen/last_seen в dga, cloud_tunnel, typosquatting.

Все три детектора ходят по state.dns_queries (Counter без ts).
fix_30 добавил dns_query_ts_by_name: dict[str, list[float]] —
теперь берём min/max и кладём в Finding.

После фикса DGA/cloud_tunnel/typosquatting видны в timeline и
kill-chain фазах (c2, initial_access, c2 соответственно).
"""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError, assert_applied

FIX_ID = "31-timeline-dns-detectors"
TITLE = "timeline: first_seen/last_seen в dga/cloud_tunnel/typosquatting"


def _ts_for(name: str, state) -> tuple[float | None, float | None]:
    ts_list = state.dns_query_ts_by_name.get(name)
    if not ts_list:
        return None, None
    return min(ts_list), max(ts_list)


# ======================= dga ===========================================
REL_DGA = "paradox/detectors/dga.py"

_OLD_DGA_FINDING = """            confidence = min(
                0.95,
                0.5 + (entropy - config.dga_entropy_threshold) / 2.0,
            )

            findings.append(Finding(
                type="dga_domain",
                value=name,
                confidence=round(confidence, 3),
                evidence={
                    "label": label,
                    "entropy": round(entropy, 3),
                    "queries": count,
                },
            ))"""

_NEW_DGA_FINDING = """            confidence = min(
                0.95,
                0.5 + (entropy - config.dga_entropy_threshold) / 2.0,
            )

            ts_list = state.dns_query_ts_by_name.get(name)
            first_seen = min(ts_list) if ts_list else None
            last_seen = max(ts_list) if ts_list else None

            findings.append(Finding(
                type="dga_domain",
                value=name,
                confidence=round(confidence, 3),
                evidence={
                    "label": label,
                    "entropy": round(entropy, 3),
                    "queries": count,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            ))"""


# ======================= cloud_tunnel ==================================
REL_CLOUD = "paradox/detectors/cloud_tunnel.py"

_OLD_CLOUD_FINDING = """            findings.append(Finding(
                type="cloud_tunnel_domain",
                value=name,
                confidence=0.7,
                evidence={
                    "matched_suffix": match,
                    "queries": count,
                },
            ))"""

_NEW_CLOUD_FINDING = """            ts_list = state.dns_query_ts_by_name.get(name)
            first_seen = min(ts_list) if ts_list else None
            last_seen = max(ts_list) if ts_list else None

            findings.append(Finding(
                type="cloud_tunnel_domain",
                value=name,
                confidence=0.7,
                evidence={
                    "matched_suffix": match,
                    "queries": count,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            ))"""


# ======================= typosquatting =================================
REL_TYPO = "paradox/detectors/typosquatting.py"

_OLD_TYPO_FINDING = """            brand, kind = match
            confidence = 0.75 if kind == "levenshtein" else 0.65
            findings.append(Finding(
                type="typosquatting",
                value=domain,
                confidence=confidence,
                evidence={
                    "brand": brand,
                    "kind": kind,
                    "label": sld,
                    "queries": count,
                },
            ))"""

_NEW_TYPO_FINDING = """            brand, kind = match
            confidence = 0.75 if kind == "levenshtein" else 0.65
            ts_list = state.dns_query_ts_by_name.get(domain)
            first_seen = min(ts_list) if ts_list else None
            last_seen = max(ts_list) if ts_list else None
            findings.append(Finding(
                type="typosquatting",
                value=domain,
                confidence=confidence,
                evidence={
                    "brand": brand,
                    "kind": kind,
                    "label": sld,
                    "queries": count,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            ))"""


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_DGA, _OLD_DGA_FINDING, _NEW_DGA_FINDING, required=False):
        changed = True
    if patch(root, REL_CLOUD, _OLD_CLOUD_FINDING, _NEW_CLOUD_FINDING, required=False):
        changed = True
    if patch(root, REL_TYPO, _OLD_TYPO_FINDING, _NEW_TYPO_FINDING, required=False):
        changed = True
    assert_applied(root, REL_DGA, "first_seen=first_seen")
    assert_applied(root, REL_CLOUD, "first_seen=first_seen")
    assert_applied(root, REL_TYPO, "first_seen=first_seen")
    return changed