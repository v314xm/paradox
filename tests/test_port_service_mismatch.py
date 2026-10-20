"""Тесты правила port_service_mismatch (протокольный туннель)."""
from paradox.contradictions.base import Fact
from paradox.contradictions.rules.f_port_service_mismatch import (
    PortServiceMismatchRule,
)


def _fact(protocol, src, dst, port, extra=None):
    return Fact(
        source=protocol,
        subject=src,
        predicate="protocol_on_port",
        value=protocol,
        ts=0.0,
        confidence=0.95,
        evidence={"dst_ip": dst, "dst_port": port, "src_port": 54321,
                  **(extra or {})},
    )


# 1. TLS на 22 (SSH) → high
def test_tls_on_ssh_high():
    facts = [_fact("tls", "192.168.1.5", "10.0.0.1", 22,
                   {"sni": "evil.com"})]
    rule = PortServiceMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "high"
    assert res[0].subject == "192.168.1.5"
    assert "evil.com" in res[0].resolution_hint


# 2. HTTP на 445 (SMB) → high
def test_http_on_smb_high():
    facts = [_fact("http", "192.168.1.5", "10.0.0.2", 445,
                   {"method": "POST"})]
    rule = PortServiceMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "high"


# 3. HTTP на 3306 (MySQL) → medium
def test_http_on_mysql_medium():
    facts = [_fact("http", "192.168.1.5", "10.0.0.3", 3306)]
    rule = PortServiceMismatchRule()
    res = rule.find_contradictions(facts)
    assert len(res) == 1
    assert res[0].severity == "medium"


# 4. TLS на 443 — не в таблице, игнор
def test_tls_on_443_no_contradiction():
    facts = [_fact("tls", "192.168.1.5", "10.0.0.4", 443)]
    rule = PortServiceMismatchRule()
    assert rule.find_contradictions(facts) == []


# 5. TLS на 25 (SMTP, STARTTLS разрешён) — не срабатывает
def test_tls_on_smtp_starttls_ok():
    facts = [_fact("tls", "192.168.1.5", "10.0.0.5", 25)]
    rule = PortServiceMismatchRule()
    assert rule.find_contradictions(facts) == []
