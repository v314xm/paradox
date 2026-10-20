"""Тесты правила sni_without_dns."""
from paradox.contradictions.base import Fact
from paradox.contradictions.rules.a_sni_without_dns import (
    SniWithoutDnsRule,
)


def _sni(src, value, dst_ip="1.2.3.4", resolved=False):
    return Fact(
        source="sni",
        subject=src,
        predicate="sni",
        value=value,
        ts=0.0,
        confidence=0.9,
        evidence={
            "dst_ip": dst_ip,
            "dst_port": 443,
            "src_port": 50000,
            "resolved": resolved,
        },
    )


def test_unresolved_sni_triggers():
    facts = [_sni("192.168.1.5", "evil.example", resolved=False)]
    rule = SniWithoutDnsRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"
    assert res[0].severity == "medium"
    assert "evil.example" in res[0].resolution_hint


def test_resolved_sni_no_contradiction():
    facts = [_sni("192.168.1.5", "ok.example", resolved=True)]
    rule = SniWithoutDnsRule()
    assert rule.find_contradictions(facts) == []


def test_mixed_resolved_and_unresolved():
    facts = [
        _sni("192.168.1.5", "resolved.example", resolved=True),
        _sni("192.168.1.5", "evil1.example", resolved=False),
        _sni("192.168.1.5", "evil2.example", resolved=False),
    ]
    rule = SniWithoutDnsRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    values = {f.value for f in res[0].facts}
    assert "evil1.example" in values
    assert "evil2.example" in values
    assert "resolved.example" not in values


def test_dedup_same_sni_many_flows():
    facts = [
        _sni("192.168.1.5", "evil.example", dst_ip="1.2.3.4"),
        _sni("192.168.1.5", "evil.example", dst_ip="5.6.7.8"),
        _sni("192.168.1.5", "evil.example", dst_ip="9.10.11.12"),
    ]
    rule = SniWithoutDnsRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert len(res[0].facts) == 1


def test_different_clients_isolated():
    facts = [
        _sni("192.168.1.5", "evil.example", resolved=False),
        _sni("192.168.1.6", "ok.example", resolved=True),
    ]
    rule = SniWithoutDnsRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"
