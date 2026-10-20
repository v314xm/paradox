"""
Тесты DNSTunnelingDetector.

Проверяем:
- длинные уникальные qname под одним base → finding
- короткие qname (DGA) → не finding
- обычные домены → не finding
- мало запросов → не finding
- allowlist (DoH) → не finding

Важно:
- qname в тестах длиннее dns_tunneling_min_qname_length (50).
- total_queries = sum(counts), порог dns_tunneling_min_queries (50).
  В тестах ставим count=2 на qname, чтобы 30 unique давали 60 total.
"""
from paradox.config import Config
from paradox.detectors.dns_tunneling import DNSTunnelingDetector
from paradox.models import CaptureState


# 35-символьный префикс. С "000000.dns.attacker.com" даёт ~58 символов —
# уверенно выше порога 50.
_LONG_PREFIX = "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQK000"

# Каждый qname повторяется по 2 раза, чтобы total_queries >= 50.
# В реальном DNS-туннеле запросов будет 1000+, здесь — минимально достаточное.
_QUERY_COUNT = 2


def _state(src_ip, qnames):
    """qnames: dict[qname -> count]."""
    state = CaptureState()
    state.dns_queries_by_src[src_ip] = dict(qnames)
    return state


def test_dns_tunneling_detects_long_unique_subdomains():
    """30 длинных уникальных qname под attacker.com — finding."""
    qnames = {
        f"{_LONG_PREFIX}{i:06d}.dns.attacker.com": _QUERY_COUNT
        for i in range(30)
    }
    state = _state("192.168.1.100", qnames)
    findings = DNSTunnelingDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].type == "dns_tunneling"
    assert findings[0].evidence["base_domain"] == "attacker.com"
    assert findings[0].evidence["long_qnames_count"] >= 20
    assert findings[0].confidence >= 0.7


def test_dns_tunneling_ignores_short_dga():
    """DGA-поддомены короткие — не DNS tunneling."""
    qnames = {
        f"dackrpbfnmwjl{i}.pwned.se": _QUERY_COUNT
        for i in range(50)
    }
    state = _state("192.168.1.100", qnames)
    findings = DNSTunnelingDetector().run(state, Config())
    assert findings == []


def test_dns_tunneling_ignores_normal():
    """Обычные домены — не tunneling."""
    qnames = {
        "www.google.com": 50,
        "mail.google.com": 30,
        "docs.google.com": 10,
    }
    state = _state("192.168.1.100", qnames)
    findings = DNSTunnelingDetector().run(state, Config())
    assert findings == []


def test_dns_tunneling_below_min_queries():
    """5 запросов — меньше порога 50."""
    qnames = {
        f"{_LONG_PREFIX}{i:06d}.dns.attacker.com": 1
        for i in range(5)
    }
    state = _state("192.168.1.100", qnames)
    findings = DNSTunnelingDetector().run(state, Config())
    assert findings == []


def test_dns_tunneling_below_min_long_qnames():
    """50 запросов, но только 3 длинных — не tunneling."""
    qnames = {
        "short.attacker.com": 47,
    }
    for i in range(3):
        qnames[f"{_LONG_PREFIX}{i:06d}.dns.attacker.com"] = 1
    state = _state("192.168.1.100", qnames)
    findings = DNSTunnelingDetector().run(state, Config())
    assert findings == []


def test_dns_tunneling_ignores_allowlist_doh():
    """DoH-сервисы не считаются tunneling."""
    qnames = {
        f"{_LONG_PREFIX}{i:06d}.dns.google": _QUERY_COUNT
        for i in range(30)
    }
    state = _state("192.168.1.100", qnames)
    findings = DNSTunnelingDetector().run(state, Config())
    assert findings == []


def test_dns_tunneling_separate_srcs():
    """Разные src с разными base — разные findings."""
    state = CaptureState()
    state.dns_queries_by_src["192.168.1.100"] = {
        f"{_LONG_PREFIX}{i:06d}.dns.attacker.com": _QUERY_COUNT
        for i in range(30)
    }
    state.dns_queries_by_src["192.168.1.101"] = {
        f"{_LONG_PREFIX}{i:06d}.dns.evil.org": _QUERY_COUNT
        for i in range(30)
    }
    findings = DNSTunnelingDetector().run(state, Config())
    assert len(findings) == 2
    values = sorted(f.value for f in findings)
    assert values == [
        "192.168.1.100 -> attacker.com",
        "192.168.1.101 -> evil.org",
    ]


def test_dns_tunneling_empty_state():
    """Пустой CaptureState — не падает."""
    findings = DNSTunnelingDetector().run(CaptureState(), Config())
    assert findings == []


def test_dns_tunneling_multiple_base_domains_same_src():
    """Один src, два base домена — два finding'а."""
    state = CaptureState()
    qnames = {}
    for i in range(30):
        qnames[f"{_LONG_PREFIX}{i:06d}.dns.attacker.com"] = _QUERY_COUNT
    for i in range(30):
        qnames[f"{_LONG_PREFIX}{i:06d}.dns.evil.org"] = _QUERY_COUNT
    state.dns_queries_by_src["192.168.1.100"] = qnames
    findings = DNSTunnelingDetector().run(state, Config())
    assert len(findings) == 2