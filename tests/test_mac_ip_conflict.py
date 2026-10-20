"""Тесты правила mac_ip_conflict (ARP spoof)."""
from paradox.contradictions.base import Fact
from paradox.contradictions.rules.b_mac_ip_conflict import (
    MacIpConflictRule,
)


def _mac_fact(ip, mac, first, last, count, conf=0.9):
    return Fact(
        source="arp",
        subject=ip,
        predicate="has_mac",
        value=mac,
        ts=first,
        confidence=conf,
        evidence={"first_ts": first, "last_ts": last, "count": count},
    )


# 1. Два устойчивых MAC, окна пересекаются → critical
def test_overlap_two_stable_macs_critical():
    facts = [
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:01", 100.0, 200.0, 10),
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:02", 150.0, 250.0, 8),
    ]
    rule = MacIpConflictRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    c = res[0]
    assert c.subject == "192.168.1.5"
    assert c.severity == "critical"
    assert c.confidence == 0.9     # min(0.9, 0.9) × 1.0
    assert len(c.facts) == 2


# 2. Окна не пересекаются → medium, hint про lease change
def test_no_overlap_medium_lease_change():
    facts = [
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:01", 100.0, 150.0, 10),
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:02", 300.0, 400.0, 10),
    ]
    rule = MacIpConflictRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    c = res[0]
    assert c.severity == "medium"
    assert "lease" in c.resolution_hint.lower() or "смену MAC" in c.resolution_hint


# 3. Пересечение есть, но один MAC — единичный пакет → high
def test_one_transient_mac_high():
    facts = [
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:01", 100.0, 200.0, 10),
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:02", 150.0, 150.5, 1, conf=0.5),
    ]
    rule = MacIpConflictRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "high"
    # min(0.9, 0.5) × 0.85 = 0.425
    assert res[0].confidence == 0.425


# 4. Один MAC на IP — не conflict
def test_single_mac_no_conflict():
    facts = [
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:01", 100.0, 200.0, 10),
    ]
    rule = MacIpConflictRule()
    assert rule.find_contradictions(facts) == []


# 5. Разные IP с разными MAC — не conflict (изоляция по subject)
def test_different_ips_no_conflict():
    facts = [
        _mac_fact("192.168.1.5", "aa:bb:cc:dd:ee:01", 100.0, 200.0, 10),
        _mac_fact("192.168.1.6", "aa:bb:cc:dd:ee:02", 100.0, 200.0, 10),
    ]
    rule = MacIpConflictRule()
    assert rule.find_contradictions(facts) == []
