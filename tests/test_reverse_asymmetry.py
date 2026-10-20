"""Тесты правила reverse_asymmetry (эксфильтрация / пропорция)."""
from paradox.contradictions.base import Fact
from paradox.contradictions.rules.e_reverse_asymmetry import (
    ReverseAsymmetryRule,
)


def _fact(subject, bytes_out, bytes_in, external="1.2.3.4",
          iport=54321, eport=443, proto="tcp"):
    total = bytes_out + bytes_in
    if bytes_in == 0:
        ratio = float("inf") if bytes_out > 0 else 1.0
    elif bytes_out == 0:
        ratio = float("inf")
    else:
        ratio = max(bytes_out, bytes_in) / min(bytes_out, bytes_in)
    return Fact(
        source="flow",
        subject=subject,
        predicate="session_asymmetry",
        value=f"{bytes_out}/{bytes_in}",
        ts=0.0,
        confidence=1.0,
        evidence={
            "external_ip": external,
            "internal_port": iport,
            "external_port": eport,
            "proto": proto,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "total_bytes": total,
            "ratio": ratio,
        },
    )


# 1. Outbound exfil: 10 МБ out / 100 КБ in → high (ratio 100)
def test_outbound_exfil_high():
    facts = [_fact("192.168.1.5", bytes_out=10_000_000, bytes_in=100_000)]
    rule = ReverseAsymmetryRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "high"
    assert res[0].subject == "192.168.1.5"
    assert "outbound" in res[0].resolution_hint


# 2. Inbound download: 5 КБ out / 5 МБ in → high
def test_inbound_download_high():
    facts = [_fact("192.168.1.5", bytes_out=5_000, bytes_in=5_000_000)]
    rule = ReverseAsymmetryRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "high"
    assert "inbound" in res[0].resolution_hint


# 3. Средняя асимметрия: 1 МБ out / 60 КБ in → medium (ratio ~17)
def test_medium_ratio():
    facts = [_fact("192.168.1.5", bytes_out=1_000_000, bytes_in=60_000)]
    rule = ReverseAsymmetryRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "medium"


# 4. Симметричный обмен — не срабатывает
def test_symmetric_no_contradiction():
    facts = [_fact("192.168.1.5", bytes_out=1_000_000, bytes_in=900_000)]
    rule = ReverseAsymmetryRule()
    assert rule.find_contradictions(facts) == []


# 5. Ниже ratio — не срабатывает
def test_low_ratio_no_contradiction():
    facts = [_fact("192.168.1.5", bytes_out=1_000_000, bytes_in=200_000)]
    rule = ReverseAsymmetryRule()
    # ratio = 5 < 10
    assert rule.find_contradictions(facts) == []