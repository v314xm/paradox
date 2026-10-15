"""Смок-тест: direct_ip_no_dns и sni_without_dns срабатывают на данных,
где DNS-ответов заведомо нет. Проверяет всю цепочку:
   CaptureState → extract_*_facts → правило → Contradiction.
"""
from pcap_triage.config import Config
from pcap_triage.models import CaptureState, FlowKey, FlowStats
from pcap_triage.contradictions.facts import (
    extract_direct_ip_facts,
    extract_tls_host_facts,
)
from pcap_triage.contradictions.rules.g_direct_ip_no_dns import (
    DirectIpNoDnsRule,
)
from pcap_triage.contradictions.rules.a_sni_without_dns import (
    SniWithoutDnsRule,
)


def _flow(src, dst, port=443, sni=None):
    """Собрать пару (FlowKey, FlowStats) без парсинга pcap."""
    key = FlowKey(
        proto="tcp", src_ip=src, dst_ip=dst,
        src_port=50000, dst_port=port,
    )
    stats = FlowStats(
        packets=10, bytes_sent=1000,
        first_ts=1.0, last_ts=2.0, sni=sni,
    )
    return key, stats


# === sni_without_dns ===

def test_sni_without_dns_triggers():
    """SNI=evil.example, DNS-ответа нет → правило срабатывает."""
    state = CaptureState()
    k, f = _flow("192.168.1.5", "1.2.3.4", sni="evil.example")
    state.flows[k] = f

    config = Config()
    facts = extract_tls_host_facts(state, config)
    sni_facts = [x for x in facts if x.source == "sni"]
    assert len(sni_facts) == 1
    assert sni_facts[0].value == "evil.example"
    assert sni_facts[0].evidence["resolved"] is False

    res = SniWithoutDnsRule().find_contradictions(facts)
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"
    assert "evil.example" in res[0].resolution_hint


def test_sni_with_dns_no_contradiction():
    """SNI=ok.example, DNS-ответ есть → правило молчит."""
    state = CaptureState()
    k, f = _flow("192.168.1.5", "1.2.3.4", sni="ok.example")
    state.flows[k] = f
    state.dns_answers_by_name["ok.example"] = {"1.2.3.4"}
    state.dns_answers_by_ip["1.2.3.4"] = {"ok.example"}

    config = Config()
    facts = extract_tls_host_facts(state, config)
    sni_facts = [x for x in facts if x.source == "sni"]
    assert len(sni_facts) == 1
    assert sni_facts[0].evidence["resolved"] is True

    assert SniWithoutDnsRule().find_contradictions(facts) == []


def test_cname_chain_resolved():
    """SNI — CNAME-таргет (значение в dns_answers_by_name) → resolved."""
    state = CaptureState()
    k, f = _flow("192.168.1.5", "1.2.3.4", sni="cdn.foo.com")
    state.flows[k] = f
    # Клиент резолвил www.foo.com, ответ содержал CNAME cdn.foo.com
    state.dns_answers_by_name["www.foo.com"] = {"cdn.foo.com", "1.2.3.4"}

    config = Config()
    facts = extract_tls_host_facts(state, config)
    sni_facts = [x for x in facts if x.source == "sni"]
    assert len(sni_facts) == 1
    assert sni_facts[0].value == "cdn.foo.com"
    assert sni_facts[0].evidence["resolved"] is True

    assert SniWithoutDnsRule().find_contradictions(facts) == []


# === direct_ip_no_dns ===

def test_direct_ip_no_dns_triggers():
    """3 external IP без DNS-ответа → правило срабатывает."""
    state = CaptureState()
    for dst in ("1.2.3.4", "5.6.7.8", "9.10.11.12"):
        k, f = _flow("192.168.1.5", dst)
        state.flows[k] = f

    config = Config()
    facts = extract_direct_ip_facts(state, config)
    connects = [x for x in facts if x.predicate == "direct_ip_connect"]
    assert len(connects) == 3
    for c in connects:
        assert c.evidence["resolved"] is False

    res = DirectIpNoDnsRule().find_contradictions(facts)
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"


def test_direct_ip_all_resolved_no_contradiction():
    """3 connect, но все IP резолвились → правило молчит."""
    state = CaptureState()
    for dst in ("1.2.3.4", "5.6.7.8", "9.10.11.12"):
        k, f = _flow("192.168.1.5", dst)
        state.flows[k] = f
        state.dns_answers_by_ip[dst] = {"some.example"}

    config = Config()
    facts = extract_direct_ip_facts(state, config)
    assert DirectIpNoDnsRule().find_contradictions(facts) == []