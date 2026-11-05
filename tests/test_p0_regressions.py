"""Регрессии P0: живые правила, timeline и целостность типов findings.

Каждый тест закрывает конкретный дефект, найденный при аудите:
  1. reverse_asymmetry падал на flow с last_ts=None;
  2. dns_tunneling / ssh_brute_force / yara не попадали в timeline;
  3. cloud_tunnel_domain не считался victim-сигналом;
  4. DNS-ответы учитывались как запросы;
  5. sni_host_mismatch был структурно недостижим (группировка по порту);
  6. self_signed_cert не фильтровал internal dst.
"""
from __future__ import annotations

import ast
import pathlib

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether

from paradox.config import Config
from paradox.contradictions.base import Fact
from paradox.contradictions.facts import (
    extract_asymmetry_facts,
    extract_attack_facts,
)
from paradox.contradictions.rules.c_sni_host_mismatch import (
    SniHostMismatchRule,
)
from paradox.contradictions.rules.j_self_signed_cert import (
    SelfSignedCertRule,
)
from paradox.detectors import mitre_map
from paradox.detectors.dns_tunneling import DNSTunnelingDetector
from paradox.detectors.ssh_brute_force import SSHBruteForceDetector
from paradox.extractors.dns import DNSExtractor
from paradox.models import (
    _SEVERITY_BY_TYPE,
    CaptureState,
    Finding,
    FlowKey,
    FlowStats,
)
from paradox.parsers import PacketRecord
from paradox.timeline import _PHASE_BY_TYPE

_DETECTORS_DIR = (
    pathlib.Path(__file__).resolve().parents[1] / "paradox" / "detectors"
)


# === 1. reverse_asymmetry: last_ts=None не должен ронять правило ===

def test_asymmetry_facts_survive_missing_last_ts():
    state = CaptureState()
    out = FlowKey("tcp", "192.168.1.5", "1.2.3.4", 54321, 443)
    back = FlowKey("tcp", "1.2.3.4", "192.168.1.5", 443, 54321)
    # У исходящего направления есть first_ts, но нет last_ts —
    # именно этот случай раньше давал TypeError в facts.py.
    state.flows[out] = FlowStats(
        bytes_sent=10_000_000, first_ts=100.0, last_ts=None,
    )
    state.flows[back] = FlowStats(
        bytes_sent=100_000, first_ts=101.0, last_ts=102.0,
    )

    facts = extract_asymmetry_facts(state, Config())

    assert len(facts) == 1
    assert facts[0].subject == "192.168.1.5"
    assert facts[0].evidence["bytes_out"] == 10_000_000


# === 2. Типы findings: каждый эмитится и зарегистрирован ===

def _emitted_finding_types() -> set[str]:
    """Все строковые литералы type="..." в детекторах (по AST)."""
    types: set[str] = set()
    for path in _DETECTORS_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if (
                    kw.arg == "type"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    types.add(kw.value.value)
    return types


def test_every_detector_type_is_registered():
    types = _emitted_finding_types()
    assert "cloud_tunnel_domain" in types

    missing_severity = types - set(_SEVERITY_BY_TYPE)
    missing_mitre = types - set(mitre_map.MITRE_MAP)
    missing_phase = types - set(_PHASE_BY_TYPE)

    assert not missing_severity, f"нет в _SEVERITY_BY_TYPE: {missing_severity}"
    assert not missing_mitre, f"нет в MITRE_MAP: {missing_mitre}"
    assert not missing_phase, f"нет в _PHASE_BY_TYPE: {missing_phase}"


# === 3. cloud_tunnel_domain → src жертва (pivot-факты) ===

def test_cloud_tunnel_domain_marks_src_as_victim():
    finding = Finding(
        type="cloud_tunnel_domain",
        value="abc123.trycloudflare.com",
        confidence=0.7,
        src_ip="192.168.1.5",
        dst_ip="1.2.3.4",
        first_seen=10.0,
    )

    facts = extract_attack_facts([finding])

    predicates = {(f.predicate, f.subject) for f in facts}
    assert ("victim_of", "192.168.1.5") in predicates


def test_cloud_tunnel_finding_is_attributed_to_client():
    from paradox.detectors.cloud_tunnel import CloudTunnelDetector

    state = CaptureState()
    state.dns_queries["abc.trycloudflare.com"] = 2
    state.dns_queries_by_src["192.168.1.5"] = {"abc.trycloudflare.com": 2}
    state.dns_query_ts_by_name["abc.trycloudflare.com"] = [10.0, 20.0]

    findings = CloudTunnelDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].src_ip == "192.168.1.5"
    assert findings[0].first_seen == 10.0
    facts = extract_attack_facts(findings)
    assert ("victim_of", "192.168.1.5") in {
        (f.predicate, f.subject) for f in facts
    }


# === 4. DNS: ответ не считается запросом ===

def _dns_record(
    qname: str,
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "8.8.8.8",
    sport: int = 12345,
    dport: int = 53,
    response: bool = False,
    answer_ip: str = "93.184.216.34",
    rcode: int = 0,
) -> PacketRecord:
    dns = DNS(qr=1 if response else 0, rcode=rcode, qd=DNSQR(qname=qname))
    if response:
        dns.an = DNSRR(rrname=qname, type="A", rdata=answer_ip)
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / dns
    )
    return PacketRecord(
        ts=100.0,
        length=len(pkt),
        raw=bytes(pkt),
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto="udp",
        src_port=sport,
        dst_port=dport,
        payload=bytes(pkt[UDP].payload),
    )


def test_dns_response_is_not_counted_as_query():
    state = CaptureState()
    DNSExtractor().process(
        _dns_record(
            "example.com", src_ip="8.8.8.8", dst_ip="10.0.0.5",
            sport=53, dport=12345, response=True,
        ),
        state,
    )

    assert len(state.dns_queries) == 0
    assert len(state.dns_query_ts_by_name) == 0
    assert "10.0.0.5" not in state.dns_queries_by_src
    # Ответ при этом обязан быть разобран.
    assert "93.184.216.34" in state.dns_answers_by_name["example.com"]


def test_dns_query_plus_response_counts_once():
    state = CaptureState()
    extractor = DNSExtractor()
    extractor.process(_dns_record("example.com"), state)
    extractor.process(
        _dns_record(
            "example.com", src_ip="8.8.8.8", dst_ip="10.0.0.5",
            sport=53, dport=12345, response=True,
        ),
        state,
    )

    assert state.dns_queries["example.com"] == 1
    assert state.dns_queries_by_src["10.0.0.5"]["example.com"] == 1
    assert "93.184.216.34" in state.dns_answers_by_name["example.com"]


# === 5. timeline: dns_tunneling и ssh_brute_force получают ts ===

# DNSExtractor хранит qname в нижнем регистре — ts-ключи тоже.
_LONG_PREFIX = "agvsbg8gd29ybggagvsbg8gd29ybggk000"


def test_dns_tunneling_has_timestamps():
    state = CaptureState()
    qnames = {
        f"{_LONG_PREFIX}{i:06d}.dns.attacker.com": 2
        for i in range(30)
    }
    state.dns_queries_by_src["192.168.1.100"] = dict(qnames)
    for idx, qname in enumerate(qnames):
        state.dns_query_ts_by_name[qname] = [100.0 + idx, 200.0 + idx]

    findings = DNSTunnelingDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].first_seen == 100.0
    assert findings[0].last_seen == 200.0 + 29


def test_ssh_brute_force_has_timestamps():
    state = CaptureState()
    state.ssh_client_attempts[("192.168.1.5", "10.0.0.9", 22)] = 25
    state.flows[FlowKey("tcp", "192.168.1.5", "10.0.0.9", 40000, 22)] = FlowStats(
        first_ts=50.0, last_ts=70.0,
    )

    findings = SSHBruteForceDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].first_seen == 50.0
    assert findings[0].last_seen == 70.0


# === 6. sni_host_mismatch: SNI на 443 vs Host на 80 одного узла ===

def _tls_host_fact(predicate: str, value: str, dst_port: int) -> Fact:
    return Fact(
        source="sni" if predicate == "sni" else "http",
        subject="192.168.1.5",
        predicate=predicate,
        value=value,
        ts=10.0,
        confidence=0.9,
        evidence={"dst_ip": "1.2.3.4", "dst_port": dst_port},
    )


def test_sni_host_mismatch_across_ports():
    facts = [
        _tls_host_fact("sni", "example.com", 443),
        _tls_host_fact("http_host", "attacker.com", 80),
    ]

    out = SniHostMismatchRule().find_contradictions(facts)

    assert len(out) == 1
    assert out[0].rule == "sni_host_mismatch"
    assert out[0].subject == "192.168.1.5"


def test_sni_host_mismatch_same_base_domain_ignored():
    facts = [
        _tls_host_fact("sni", "www.example.com", 443),
        _tls_host_fact("http_host", "example.com", 80),
    ]

    assert SniHostMismatchRule().find_contradictions(facts) == []


# === 7. self_signed_cert: internal dst не считается аномалией ===

def test_self_signed_cert_skips_internal_dst(monkeypatch):
    import paradox.contradictions.facts as facts_mod

    def _fact(dst_ip: str) -> Fact:
        return Fact(
            source="tls_cert",
            subject="10.0.0.5",
            predicate="tls_cert",
            value="dev.local",
            ts=10.0,
            confidence=0.9,
            evidence={
                "dst_ip": dst_ip,
                "dst_port": 443,
                "is_self_signed": True,
                "subject_cn": "dev.local",
            },
        )

    monkeypatch.setattr(
        facts_mod, "extract_tls_cert_facts",
        lambda state: [_fact("10.0.0.6"), _fact("8.8.8.8")],
    )

    extracted = SelfSignedCertRule().extract_facts(
        CaptureState(), [], Config(),
    )

    assert [f.evidence["dst_ip"] for f in extracted] == ["8.8.8.8"]
    assert len(SelfSignedCertRule().find_contradictions(extracted)) == 1
