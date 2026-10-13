"""Тесты правила sni_host_mismatch (domain fronting)."""
from pcap_triage.contradictions.base import Fact
from pcap_triage.contradictions.rules.c_sni_host_mismatch import (
    SniHostMismatchRule,
)


def _fact(predicate, value, src, dst, dport=443, conf=0.9):
    return Fact(
        source=predicate,
        subject=src,
        predicate=predicate,
        value=value,
        ts=0.0,
        confidence=conf,
        evidence={"dst_ip": dst, "dst_port": dport, "src_port": 54321},
    )


# 1. SNI ≠ Host, разные SLD → high
def test_domain_fronting_high():
    facts = [
        _fact("sni", "cdn.legit.com", "192.168.1.5", "1.2.3.4"),
        _fact("http_host", "attacker.com", "192.168.1.5", "1.2.3.4"),
    ]
    rule = SniHostMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    c = res[0]
    assert c.subject == "192.168.1.5"
    assert c.severity == "high"
    # min(0.9, 0.9) × 0.9 = 0.81
    assert c.confidence == 0.81
    assert "cdn.legit.com" in c.resolution_hint
    assert "attacker.com" in c.resolution_hint


# 2. SNI == Host → норм
def test_sni_equals_host_no_contradiction():
    facts = [
        _fact("sni", "example.com", "192.168.1.5", "1.2.3.4"),
        _fact("http_host", "example.com", "192.168.1.5", "1.2.3.4"),
    ]
    rule = SniHostMismatchRule()
    assert rule.find_contradictions(facts) == []


# 3. Одна база — норм (www vs apex)
def test_same_base_domain_no_contradiction():
    facts = [
        _fact("sni", "api.example.com", "192.168.1.5", "1.2.3.4"),
        _fact("http_host", "www.example.com", "192.168.1.5", "1.2.3.4"),
    ]
    rule = SniHostMismatchRule()
    assert rule.find_contradictions(facts) == []


# 4. Только SNI, Host отсутствует → норм (не mismatch)
def test_only_sni_no_contradiction():
    facts = [
        _fact("sni", "example.com", "192.168.1.5", "1.2.3.4"),
    ]
    rule = SniHostMismatchRule()
    assert rule.find_contradictions(facts) == []


# 5. Multi-tenant: разные Hosts на одном соединении → норм (HTTP/2)
def test_multi_host_http2_no_contradiction():
    facts = [
        _fact("sni", "cdn.example.com", "192.168.1.5", "1.2.3.4"),
        _fact("http_host", "service1.com", "192.168.1.5", "1.2.3.4"),
        _fact("http_host", "service2.com", "192.168.1.5", "1.2.3.4"),
    ]
    rule = SniHostMismatchRule()
    assert rule.find_contradictions(facts) == []