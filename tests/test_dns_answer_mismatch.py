"""Тесты правила dns_answer_mismatch."""
from paradox.contradictions.base import Fact
from paradox.contradictions.rules.h_dns_answer_mismatch import (
    DnsAnswerMismatchRule,
)


def _sni(src, value, dst_ip, resolved=True, resolved_ips=None):
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
            "resolved_ips": resolved_ips or [],
        },
    )


def test_mismatch_triggers():
    facts = [_sni("192.168.1.5", "evil.example", "1.2.3.4",
                  resolved_ips=["5.6.7.8"])]
    rule = DnsAnswerMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"
    assert res[0].severity == "medium"
    assert "evil.example" in res[0].resolution_hint


def test_match_no_contradiction():
    facts = [_sni("192.168.1.5", "ok.example", "5.6.7.8",
                  resolved_ips=["5.6.7.8", "9.10.11.12"])]
    rule = DnsAnswerMismatchRule()
    assert rule.find_contradictions(facts) == []


def test_not_resolved_ignored():
    # resolved=False → это sni_without_dns, не наше правило.
    facts = [_sni("192.168.1.5", "evil.example", "1.2.3.4", resolved=False)]
    rule = DnsAnswerMismatchRule()
    assert rule.find_contradictions(facts) == []


def test_no_resolved_ips_ignored():
    # resolved=True, но resolved_ips пуст → нет терминального A.
    facts = [_sni("192.168.1.5", "cname.example", "1.2.3.4",
                  resolved=True, resolved_ips=[])]
    rule = DnsAnswerMismatchRule()
    assert rule.find_contradictions(facts) == []


def test_mixed_same_sni_dedup():
    # Один SNI, два flow: один на правильный IP, другой на левый.
    facts = [
        _sni("192.168.1.5", "ok.example", "5.6.7.8",
             resolved_ips=["5.6.7.8"]),
        _sni("192.168.1.5", "ok.example", "9.9.9.9",
             resolved_ips=["5.6.7.8"]),
    ]
    rule = DnsAnswerMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert len(res[0].facts) == 1  # только один mismatched dst_ip
    assert res[0].facts[0].evidence["dst_ip"] == "9.9.9.9"


def test_different_clients_isolated():
    facts = [
        _sni("192.168.1.5", "evil.example", "1.2.3.4",
             resolved_ips=["5.6.7.8"]),
        _sni("192.168.1.6", "ok.example", "5.6.7.8",
             resolved_ips=["5.6.7.8"]),
    ]
    rule = DnsAnswerMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"
