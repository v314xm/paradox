"""Тесты правил sni_cert_mismatch / self_signed_cert / expired_cert."""
from paradox.contradictions.base import Fact
from paradox.contradictions.rules.i_sni_cert_mismatch import (
    SniCertMismatchRule,
    _match_one,
)
from paradox.contradictions.rules.j_self_signed_cert import (
    SelfSignedCertRule,
)
from paradox.contradictions.rules.k_expired_cert import (
    ExpiredCertRule,
)


def _cert_fact(
    src="192.168.1.5",
    sni="example.com",
    subject_cn="example.com",
    issuer_cn="Test CA",
    is_self_signed=False,
    not_after="2026-12-31T23:59:59",
    not_after_ts=1798761599.0,  # ~2026-12-31
    san_dns=None,
    ts=1700000000.0,           # ~2023-11-14
    dst_ip="1.2.3.4",
    dst_port=443,
):
    return Fact(
        source="tls_cert",
        subject=src,
        predicate="tls_cert",
        value=subject_cn or "",
        ts=ts,
        confidence=0.9,
        evidence={
            "sni": sni,
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "is_self_signed": is_self_signed,
            "not_before": "2024-01-01T00:00:00",
            "not_after": not_after,
            "not_after_ts": not_after_ts,
            "san_dns": san_dns or [],
            "san_ips": [],
            "dst_ip": dst_ip,
            "dst_port": dst_port,
        },
    )


# === wildcard matching ===

def test_match_exact():
    assert _match_one("example.com", "example.com") is True


def test_match_case_insensitive():
    assert _match_one("Example.COM", "example.com") is True


def test_match_wildcard_single_level():
    assert _match_one("a.example.com", "*.example.com") is True


def test_match_wildcard_two_levels_no():
    # *.example.com НЕ matches a.b.example.com (RFC 6125)
    assert _match_one("a.b.example.com", "*.example.com") is False


def test_match_different_domain():
    assert _match_one("attacker.com", "example.com") is False


def test_match_empty():
    assert _match_one("", "example.com") is False
    assert _match_one("example.com", "") is False


# === SniCertMismatchRule ===

def test_sni_cert_mismatch_triggers():
    f = _cert_fact(sni="evil.example", subject_cn="legit.example",
                   san_dns=["legit.example"])
    res = SniCertMismatchRule().find_contradictions([f])
    assert len(res) == 1
    assert res[0].subject == "192.168.1.5"
    assert res[0].severity == "medium"


def test_sni_cert_match_no_contradiction():
    f = _cert_fact(sni="example.com", subject_cn="example.com")
    assert SniCertMismatchRule().find_contradictions([f]) == []


def test_sni_cert_san_match_no_contradiction():
    f = _cert_fact(sni="www.example.com", subject_cn="example.com",
                   san_dns=["www.example.com", "api.example.com"])
    assert SniCertMismatchRule().find_contradictions([f]) == []


def test_sni_cert_wildcard_match():
    f = _cert_fact(sni="a.example.com", subject_cn="*.example.com")
    assert SniCertMismatchRule().find_contradictions([f]) == []


def test_sni_cert_no_sni_skipped():
    f = _cert_fact(sni="", subject_cn="example.com")
    assert SniCertMismatchRule().find_contradictions([f]) == []


def test_sni_cert_no_names_skipped():
    f = _cert_fact(sni="example.com", subject_cn=None, san_dns=[])
    assert SniCertMismatchRule().find_contradictions([f]) == []


# === SelfSignedCertRule ===

def test_self_signed_triggers():
    f = _cert_fact(is_self_signed=True, subject_cn="evil.example",
                   issuer_cn="evil.example")
    res = SelfSignedCertRule().find_contradictions([f])
    assert len(res) == 1
    assert res[0].severity == "medium"


def test_not_self_signed_no_contradiction():
    f = _cert_fact(is_self_signed=False)
    assert SelfSignedCertRule().find_contradictions([f]) == []


# === ExpiredCertRule ===

def test_expired_cert_triggers():
    # not_after_ts < first_ts flow
    f = _cert_fact(
        not_after_ts=1500000000.0,   # ~2017-07
        ts=1700000000.0,             # ~2023-11
    )
    res = ExpiredCertRule().find_contradictions([f])
    assert len(res) == 1
    assert res[0].severity == "low"


def test_not_expired_no_contradiction():
    f = _cert_fact(
        not_after_ts=1798761599.0,   # ~2026-12
        ts=1700000000.0,             # ~2023-11
    )
    assert ExpiredCertRule().find_contradictions([f]) == []


def test_expired_no_timestamps_skipped():
    f = _cert_fact(not_after_ts=0.0)
    assert ExpiredCertRule().find_contradictions([f]) == []
