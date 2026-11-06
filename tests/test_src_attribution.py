"""DNS-находки привязаны к клиенту: Finding.src_ip → entities.

Без src_ip finding не попадает в build_entities: у сущности нет
findings_indices, роли victim_candidate не выставляются, в отчёте
домен висит без хоста. Одно имя могут спрашивать несколько хостов,
поэтому finding строится на пару (src_ip, домен).
"""
from collections import Counter

from paradox.aggregators.entities import build_entities
from paradox.config import Config
from paradox.detectors.cloud_tunnel import CloudTunnelDetector
from paradox.detectors.dga import DGADetector
from paradox.detectors.ip_check_service import IPCheckServiceDetector
from paradox.detectors.typosquatting import TyposquattingDetector
from paradox.models import CaptureState, FlowKey, FlowStats

DGA_DOMAIN = "kq3jf9zxqp1mwv7n.ru"


def _state_with_dns(domain: str, srcs: list[str] | None = None) -> CaptureState:
    state = CaptureState()
    state.dns_queries[domain] = 1
    for src in srcs or []:
        state.dns_queries_by_src[src] = Counter({domain: 1})
    return state


def test_dga_sets_src_ip():
    state = _state_with_dns(DGA_DOMAIN, ["10.0.0.5"])

    findings = DGADetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].src_ip == "10.0.0.5"
    assert findings[0].evidence["src_ip"] == "10.0.0.5"


def test_dga_splits_finding_per_client():
    state = _state_with_dns(DGA_DOMAIN)
    state.dns_queries[DGA_DOMAIN] = 4
    state.dns_queries_by_src["10.0.0.5"] = Counter({DGA_DOMAIN: 3})
    state.dns_queries_by_src["10.0.0.6"] = Counter({DGA_DOMAIN: 1})

    findings = DGADetector().run(state, Config())

    assert [f.src_ip for f in findings] == ["10.0.0.5", "10.0.0.6"]
    assert [f.evidence["queries"] for f in findings] == [3, 1]


def test_dga_without_per_src_state_keeps_old_behavior():
    state = _state_with_dns(DGA_DOMAIN)

    findings = DGADetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].src_ip is None


def test_typosquatting_sets_src_ip():
    state = _state_with_dns("event-datamicrosoft.live", ["10.0.0.5"])

    findings = TyposquattingDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].src_ip == "10.0.0.5"


def test_cloud_tunnel_sets_src_ip():
    state = _state_with_dns("abc.trycloudflare.com", ["10.0.0.5"])

    findings = CloudTunnelDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].src_ip == "10.0.0.5"


def test_ip_check_service_sets_src_ip_from_dns():
    state = _state_with_dns("ip-api.com", ["10.0.0.5"])

    findings = IPCheckServiceDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].src_ip == "10.0.0.5"
    assert findings[0].evidence["sources"] == ["dns"]


def test_ip_check_service_merges_sources_of_one_client():
    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="10.0.0.5", dst_ip="208.95.112.1",
        src_port=50000, dst_port=443,
    )
    flow = FlowStats(packets=2, bytes_sent=100)
    flow.sni = "ip-api.com"
    state.flows[key] = flow

    findings = IPCheckServiceDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].src_ip == "10.0.0.5"
    assert set(findings[0].evidence["sources"]) == {"sni", "direct_ip"}


def test_dga_finding_lands_on_internal_entity():
    state = _state_with_dns(DGA_DOMAIN, ["10.0.0.5"])

    findings = DGADetector().run(state, Config())
    entities = build_entities(state, findings, Config())

    victim = next(e for e in entities.internal if e.ip == "10.0.0.5")
    assert victim.findings_indices == [0]
    assert "victim_candidate" in victim.roles
