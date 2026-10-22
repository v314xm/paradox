"""Fix #30: dns_query_ts_by_name в CaptureState + сбор в DNSExtractor.

DNS-based детекторы (dga, cloud_tunnel, typosquatting) не имеют
timestamps, потому что state.dns_queries — это Counter без ts.
Timeline их пропускает, kill-chain фазы не видны.

Фикс: новое поле dns_query_ts_by_name: dict[str, list[float]] в
CaptureState, заполняется в DNSExtractor на каждом DNS-запросе.
Аналог dns_nxdomain_ts_by_src (уже существует для nxdomain_burst).

Multi-pcap: merge_capture_states сливает списки, иначе длинный
горизонт теряет ts и timeline дырявый.
"""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError, assert_applied

FIX_ID = "30-dns-query-ts"
TITLE = "dns_query_ts_by_name: CaptureState + DNSExtractor + multi_pcap"

# === 1. CaptureState: новое поле =======================================
REL_MODELS = "paradox/models.py"

_OLD_MODELS = """    # v0.9.0: timestamps каждого NXDOMAIN по src_ip.
    # Нужно nxdomain_burst для скользящего окна. Раньше
    # dns_nxdomain_by_src считал за весь файл — на FIN-2015 давало
    # 93 findings, из которых большинство — размазанные по часу
    # опечатки. Здесь храним ts, окно считаем в детекторе.
    dns_nxdomain_ts_by_src: dict[str, list[float]] = field(
        default_factory=dict,
    )"""

_NEW_MODELS = """    # v0.9.0: timestamps каждого NXDOMAIN по src_ip.
    # Нужно nxdomain_burst для скользящего окна. Раньше
    # dns_nxdomain_by_src считал за весь файл — на FIN-2015 давало
    # 93 findings, из которых большинство — размазанные по часу
    # опечатки. Здесь храним ts, окно считаем в детекторе.
    dns_nxdomain_ts_by_src: dict[str, list[float]] = field(
        default_factory=dict,
    )

    # v1.3.1: timestamps DNS-запросов по имени домена.
    # Нужно dga/cloud_tunnel/typosquatting для first_seen/last_seen
    # в Finding — иначе timeline их пропускает.
    # Аналог dns_nxdomain_ts_by_src, но по имени, а не по src.
    dns_query_ts_by_name: dict[str, list[float]] = field(
        default_factory=dict,
    )"""

# === 2. DNSExtractor: сбор ts ==========================================
REL_DNS_EXT = "paradox/extractors/dns.py"

_OLD_DNS_EXT = """        state.dns_queries[name] += 1

        # DNS по источнику: клиент — тот, кто спрашивал."""

_NEW_DNS_EXT = """        state.dns_queries[name] += 1

        # v1.3.1: timestamps запросов по имени — для dga/cloud_tunnel/
        # typosquatting, чтобы timeline их видел.
        state.dns_query_ts_by_name.setdefault(name, []).append(record.ts)

        # DNS по источнику: клиент — тот, кто спрашивал."""

# === 3. multi_pcap: слияние ============================================
REL_MULTI = "paradox/multi_pcap.py"

_OLD_MULTI = """        for src, ts_list in st.dns_nxdomain_ts_by_src.items():
            merged.dns_nxdomain_ts_by_src.setdefault(src, []).extend(ts_list)"""

_NEW_MULTI = """        for src, ts_list in st.dns_nxdomain_ts_by_src.items():
            merged.dns_nxdomain_ts_by_src.setdefault(src, []).extend(ts_list)

        for name, ts_list in st.dns_query_ts_by_name.items():
            merged.dns_query_ts_by_name.setdefault(name, []).extend(ts_list)"""


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_MODELS, _OLD_MODELS, _NEW_MODELS, required=False):
        changed = True
    if patch(root, REL_DNS_EXT, _OLD_DNS_EXT, _NEW_DNS_EXT, required=False):
        changed = True
    if patch(root, REL_MULTI, _OLD_MULTI, _NEW_MULTI, required=False):
        changed = True
    assert_applied(root, REL_MODELS, "dns_query_ts_by_name")
    assert_applied(root, REL_DNS_EXT, "dns_query_ts_by_name")
    assert_applied(root, REL_MULTI, "dns_query_ts_by_name")
    return changed