"""Тесты правила ja3_ua_mismatch (спуфинг TLS-стека / UA)."""
from pcap_triage.contradictions.base import Fact
from pcap_triage.contradictions.rules.d_ja3_ua_mismatch import (
    Ja3UaMismatchRule,
)


def _ja3_fact(src, family, hash_="abc", dst="1.2.3.4", port=443):
    return Fact(
        source="ja3",
        subject=src,
        predicate="uses_ja3",
        value=hash_,
        ts=0.0,
        confidence=0.9,
        evidence={"family": family, "dst_ip": dst, "dst_port": port},
    )


def _ua_fact(src, family, value="some-ua", dst="1.2.3.4", port=80):
    return Fact(
        source="http_ua",
        subject=src,
        predicate="uses_ua",
        value=value,
        ts=0.0,
        confidence=0.85,
        evidence={"family": family, "dst_ip": dst, "dst_port": port},
    )


# 1. tool JA3 + browser UA → high
def test_tool_ja3_browser_ua_high():
    facts = [
        _ja3_fact("192.168.1.5", "tool"),
        _ua_fact("192.168.1.5", "chrome", "Mozilla/5.0 Chrome/120"),
    ]
    rule = Ja3UaMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "high"
    assert res[0].confidence == 0.75


# 2. malware JA3 + любой UA → critical
def test_malware_ja3_critical():
    facts = [
        _ja3_fact("192.168.1.5", "malware"),
        _ua_fact("192.168.1.5", "chrome"),
    ]
    rule = Ja3UaMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "critical"
    assert res[0].confidence == 0.85


# 3. browser JA3 + tool UA → medium
def test_browser_ja3_tool_ua_medium():
    facts = [
        _ja3_fact("192.168.1.5", "browser_placeholder"),  # подменяем
        _ua_fact("192.168.1.5", "python"),
    ]
    # family "browser_placeholder" не входит ни в _BROWSER_FAMILIES,
    # ни в _TOOL_FAMILIES — не сработает. Нужен реальный "chrome".
    facts[0] = _ja3_fact("192.168.1.5", "chrome")
    rule = Ja3UaMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "medium"


# 4. Совместимые семейства (tool + python) — не срабатывает
def test_tool_ja3_tool_ua_no_contradiction():
    facts = [
        _ja3_fact("192.168.1.5", "tool"),
        _ua_fact("192.168.1.5", "python", "python-requests/2.31"),
    ]
    rule = Ja3UaMismatchRule()
    assert rule.find_contradictions(facts) == []


# 5. Разные src — не смешиваем
def test_different_clients_isolated():
    facts = [
        _ja3_fact("192.168.1.5", "tool"),
        _ua_fact("192.168.1.6", "chrome"),
    ]
    rule = Ja3UaMismatchRule()
    assert rule.find_contradictions(facts) == []