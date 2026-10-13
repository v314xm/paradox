"""Тесты правила direct_ip_no_dns (hardcoded IP / прямой C2)."""
from pcap_triage.contradictions.base import Fact
from pcap_triage.contradictions.rules.g_direct_ip_no_dns import (
    DirectIpNoDnsRule,
)


def _connect(src, dst, ports=None, bytes_sent=5000):
    return Fact(
        source="flow",
        subject=src,
        predicate="direct_ip_connect",
        value=dst,
        ts=0.0,
        confidence=0.9,
        evidence={
            "dst_ip": dst,
            "ports": ports or [443],
            "bytes_sent": bytes_sent,
        },
    )


def _dns(src, count=5):
    return Fact(
        source="dns",
        subject=src,
        predicate="makes_dns_queries",
        value="",
        ts=0.0,
        confidence=0.9,
        evidence={"count": count, "sample": ["example.com"]},
    )


# 1. 3+ dst, DNS нет → medium
def test_three_dsts_no_dns_medium():
    facts = [
        _connect("192.168.1.5", "1.2.3.4"),
        _connect("192.168.1.5", "5.6.7.8"),
        _connect("192.168.1.5", "9.10.11.12"),
    ]
    rule = DirectIpNoDnsRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "medium"
    assert res[0].subject == "192.168.1.5"
    assert "DNS-запросов — ноль" in res[0].resolution_hint


# 2. 1 dst, 10+ ports → срабатывает (много обращений к одному IP)
def test_one_dst_many_ports():
    facts = [
        _connect("192.168.1.5", "1.2.3.4",
                 ports=list(range(1000, 1010))),
    ]
    rule = DirectIpNoDnsRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1


# 3. Есть DNS-запросы → не срабатывает
def test_with_dns_no_contradiction():
    facts = [
        _connect("192.168.1.5", "1.2.3.4"),
        _connect("192.168.1.5", "5.6.7.8"),
        _connect("192.168.1.5", "9.10.11.12"),
        _dns("192.168.1.5"),
    ]
    rule = DirectIpNoDnsRule()
    assert rule.find_contradictions(facts) == []


# 4. Один dst, один порт → шум, не срабатывает
def test_single_connect_no_contradiction():
    facts = [_connect("192.168.1.5", "1.2.3.4", ports=[443])]
    rule = DirectIpNoDnsRule()
    assert rule.find_contradictions(facts) == []


# 5. Разные клиенты изолированы
def test_different_clients_isolated():
    facts = [
        _connect("192.168.1.5", "1.2.3.4"),
        _connect("192.168.1.5", "5.6.7.8"),
        _connect("192.168.1.5", "9.10.11.12"),
        _dns("192.168.1.6"),       # другой клиент, у него DNS есть
    ]
    rule = DirectIpNoDnsRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"