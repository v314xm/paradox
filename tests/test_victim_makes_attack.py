"""Тесты правила victim_makes_attack (PIVOT)."""
from paradox.contradictions.base import Fact
from paradox.contradictions.facts import extract_attack_facts
from paradox.contradictions.rules.e_victim_makes_attack import (
    VictimMakesAttackRule,
)
from paradox.models import Finding


def _finding(ftype, src, dst, conf=0.85, ts=100.0):
    return Finding(
        type=ftype,
        value=f"{src} -> {dst}",
        confidence=conf,
        evidence={"src_ip": src, "dst_ip": dst},
        first_seen=ts,
    )


# 1. Полярность attack-типов: src=attacker, dst=victim
def test_extract_attack_facts_polarity():
    f = _finding("brute_force", "10.0.0.1", "192.168.1.5")
    facts = extract_attack_facts([f])
    preds = {(x.subject, x.predicate, x.value) for x in facts}
    assert ("192.168.1.5", "victim_of",   "10.0.0.1")  in preds
    assert ("10.0.0.1",   "attacker_of", "192.168.1.5") in preds


# 2. Полярность victim-signal-типов: src=victim, dst=C2
def test_extract_attack_facts_victim_signal():
    f = _finding("beaconing", "192.168.1.5", "1.2.3.4")
    facts = extract_attack_facts([f])
    preds = {(x.subject, x.predicate, x.value) for x in facts}
    assert ("192.168.1.5", "victim_of",   "1.2.3.4") in preds
    assert ("1.2.3.4",     "attacker_of", "192.168.1.5") in preds


# 3. Pivot: X — victim_of(A) и attacker_of(B) → critical, conf cap 0.90
def test_pivot_happy_path():
    facts = [
        Fact("finding", "192.168.1.12", "victim_of",   "10.0.1.50", 10.0, 0.95),
        Fact("finding", "192.168.1.12", "attacker_of", "192.168.1.1", 20.0, 0.90),
    ]
    rule = VictimMakesAttackRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    c = res[0]
    assert c.rule == "victim_makes_attack"
    assert c.subject == "192.168.1.12"
    assert c.severity == "critical"
    assert c.confidence == 0.90           # потолок
    assert len(c.facts) == 2
    assert c.priority == 0.90              # severity=1.0 × conf=0.90


# 4. Self-loop: X атакует X — не pivot
def test_self_loop_not_flagged():
    facts = [
        Fact("finding", "10.0.0.1", "victim_of",   "10.0.0.1", 10.0, 0.9),
        Fact("finding", "10.0.0.1", "attacker_of", "10.0.0.1", 10.0, 0.9),
    ]
    rule = VictimMakesAttackRule()
    assert rule.find_contradictions(facts) == []


# 5. Обратный порядок timestamps → hint про NAT/proxy
def test_reverse_timestamps_hint():
    facts = [
        Fact("finding", "10.0.0.5", "victim_of",   "10.0.0.9", 100.0, 0.9),
        Fact("finding", "10.0.0.5", "attacker_of", "10.0.0.3", 50.0,  0.9),
    ]
    rule = VictimMakesAttackRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    hint = res[0].resolution_hint or ""
    assert "обратный" in hint.lower() or "NAT" in hint