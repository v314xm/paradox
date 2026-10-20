"""
Unit-тесты build_entities.

Работаем с CaptureState руками. Без pcap, без scapy.
"""
from collections import Counter

from paradox.aggregators.entities import build_entities
from paradox.config import Config
from paradox.models import CaptureState, Finding, FlowKey, FlowStats


def _add_flow(state, src_ip, dst_ip, sport, dport, bytes_sent=100,
              first_ts=1.0, last_ts=1.0, sni=None):
    key = FlowKey(proto="tcp", src_ip=src_ip, dst_ip=dst_ip,
                  src_port=sport, dst_port=dport)
    fs = FlowStats(packets=1, bytes_sent=bytes_sent,
                   first_ts=first_ts, last_ts=last_ts)
    fs.sni = sni
    state.flows[key] = fs


# ---------- классификация ----------

def test_internal_external_split():
    state = CaptureState()
    _add_flow(state, "192.168.1.10", "8.8.8.8", 54000, 53)

    entities = build_entities(state, [], Config())

    internal_ips = [e.ip for e in entities.internal]
    external_ips = [e.ip for e in entities.external]

    assert "192.168.1.10" in internal_ips
    assert "8.8.8.8" in external_ips
    assert "8.8.8.8" not in internal_ips


# ---------- агрегация ----------

def test_flow_and_bytes_aggregation():
    state = CaptureState()
    _add_flow(state, "192.168.1.10", "8.8.8.8", 54000, 53, bytes_sent=100)
    _add_flow(state, "192.168.1.10", "8.8.8.8", 54001, 53, bytes_sent=200)
    _add_flow(state, "8.8.8.8", "192.168.1.10", 53, 54000, bytes_sent=50)

    entities = build_entities(state, [], Config())

    client = next(e for e in entities.internal if e.ip == "192.168.1.10")
    server = next(e for e in entities.external if e.ip == "8.8.8.8")

    assert client.flows_out == 2
    assert client.flows_in == 1
    assert client.bytes_out == 300
    assert client.bytes_in == 50

    assert server.flows_in == 2
    assert server.flows_out == 1
    assert server.bytes_in == 300
    assert server.bytes_out == 50


# ---------- SNI ----------

def test_sni_written_to_both_ends():
    state = CaptureState()
    _add_flow(state, "192.168.1.10", "203.0.113.5", 54000, 443,
              sni="example.com")

    entities = build_entities(state, [], Config())

    client = next(e for e in entities.internal if e.ip == "192.168.1.10")
    server = next(e for e in entities.external if e.ip == "203.0.113.5")

    assert "example.com" in client.sni_domains
    assert "example.com" in server.sni_domains


# ---------- DNS by src ----------

def test_dns_names_attached_to_client():
    state = CaptureState()
    state.dns_queries_by_src["192.168.1.10"] = Counter({
        "google.com": 5, "yandex.ru": 3,
    })

    entities = build_entities(state, [], Config())

    client = next(e for e in entities.internal if e.ip == "192.168.1.10")
    assert "google.com" in client.dns_names
    assert "yandex.ru" in client.dns_names


# ---------- findings ----------

def test_nxdomain_burst_creates_victim_candidate():
    state = CaptureState()
    findings = [Finding(type="nxdomain_burst", value="192.168.1.10",
                        confidence=0.85)]

    entities = build_entities(state, findings, Config())

    client = next(e for e in entities.internal if e.ip == "192.168.1.10")
    assert "victim_candidate" in client.roles
    assert 0 in client.findings_indices


def test_suspicious_port_external_creates_c2_candidate():
    state = CaptureState()
    findings = [Finding(
        type="suspicious_port",
        value="203.0.113.66:4444",
        confidence=0.5,
        evidence={"src_ip": "192.168.1.10", "dst_ip": "203.0.113.66",
                  "dst_port": 4444},
    )]

    entities = build_entities(state, findings, Config())

    victim = next(e for e in entities.internal if e.ip == "192.168.1.10")
    c2 = next(e for e in entities.external if e.ip == "203.0.113.66")

    assert "victim_candidate" in victim.roles
    assert "c2_candidate" in c2.roles


# ---------- special IPs ----------

def test_special_ips_excluded():
    state = CaptureState()
    _add_flow(state, "192.168.1.10", "239.255.255.250", 54000, 1900)
    _add_flow(state, "192.168.1.10", "255.255.255.255", 54000, 67)
    _add_flow(state, "127.0.0.1", "192.168.1.10", 54000, 80)

    entities = build_entities(state, [], Config())

    all_ips = {e.ip for e in entities.internal + entities.external}
    assert "239.255.255.250" not in all_ips
    assert "255.255.255.255" not in all_ips
    assert "127.0.0.1" not in all_ips
    assert "192.168.1.10" in all_ips


# ---------- gateway ----------

def test_gateway_candidate_role():
    state = CaptureState()
    for i in range(60):
        dst = f"203.0.113.{i % 15 + 1}"
        _add_flow(state, "192.168.1.1", dst, 54000 + i, 443)

    entities = build_entities(state, [], Config())

    gw = next(e for e in entities.internal if e.ip == "192.168.1.1")
    assert "gateway_candidate" in gw.roles


# ---------- brute_force roles ----------

def test_brute_force_creates_attacker_and_victim():
    """brute_force finding → src_ip=attacker_candidate, dst_ip=victim_candidate."""
    state = CaptureState()
    findings = [Finding(
        type="brute_force",
        value="10.0.1.50 -> 192.168.1.12:80",
        confidence=0.95,
        evidence={
            "src_ip": "10.0.1.50",
            "dst_ip": "192.168.1.12",
            "dst_port": 80,
            "flow_count": 230,
        },
    )]

    entities = build_entities(state, findings, Config())

    attacker = next(e for e in entities.internal if e.ip == "10.0.1.50")
    victim = next(e for e in entities.internal if e.ip == "192.168.1.12")

    assert "attacker_candidate" in attacker.roles
    assert "victim_candidate" in victim.roles
    assert "attacker_candidate" not in victim.roles


def test_suspicious_port_src_is_victim_not_attacker():
    """suspicious_port → src_ip=victim_candidate (жертва стучится наружу)."""
    state = CaptureState()
    findings = [Finding(
        type="suspicious_port",
        value="203.0.113.66:4444",
        confidence=0.5,
        evidence={
            "src_ip": "192.168.1.10",
            "dst_ip": "203.0.113.66",
            "dst_port": 4444,
        },
    )]

    entities = build_entities(state, findings, Config())

    victim = next(e for e in entities.internal if e.ip == "192.168.1.10")
    c2 = next(e for e in entities.external if e.ip == "203.0.113.66")

    assert "victim_candidate" in victim.roles
    assert "attacker_candidate" not in victim.roles
    assert "c2_candidate" in c2.roles
