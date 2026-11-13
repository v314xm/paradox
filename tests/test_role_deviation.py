"""Тесты правила role_deviation: отклонение поведения от роли хоста."""
from paradox.config import Config
from paradox.contradictions.rules.l_role_deviation import RoleDeviationRule
from paradox.host_profiler import HostProfiler
from paradox.models import (
    CaptureState,
    FlowKey,
    FlowStats,
    HostIdentity,
)


def _host(state, ip, mac):
    state.host_identities[ip] = HostIdentity(ip=ip, mac=mac)


def _flow(state, src, sport, dst, dport, proto="tcp", bytes_sent=100):
    key = FlowKey(
        proto=proto, src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport,
    )
    flow = FlowStats(packets=1, bytes_sent=bytes_sent)
    flow.first_ts = 1000.0
    flow.last_ts = 1001.0
    state.flows[key] = flow


# ---------------------------------------------------------------------
# baseline role по OUI
# ---------------------------------------------------------------------

def test_assign_role_apple_workstation():
    state = CaptureState()
    _host(state, "10.0.0.5", "3c:07:54:00:00:01")  # Apple
    assert HostProfiler().assign_role(state, Config(), "10.0.0.5") == "workstation"


def test_assign_role_vmware_server():
    state = CaptureState()
    _host(state, "10.0.0.6", "00:0c:29:00:00:01")  # VMware
    assert HostProfiler().assign_role(state, Config(), "10.0.0.6") == "server"


def test_assign_role_cisco_network_device():
    state = CaptureState()
    _host(state, "10.0.0.1", "00:1b:0c:00:00:01")  # Cisco
    assert (
        HostProfiler().assign_role(state, Config(), "10.0.0.1")
        == "network_device"
    )


def test_assign_role_unknown_oui():
    state = CaptureState()
    _host(state, "10.0.0.7", "aa:bb:cc:00:00:01")
    assert HostProfiler().assign_role(state, Config(), "10.0.0.7") == "unknown"


def test_assign_role_no_mac_unknown():
    state = CaptureState()
    assert HostProfiler().assign_role(state, Config(), "10.0.0.8") == "unknown"


# ---------------------------------------------------------------------
# поведение
# ---------------------------------------------------------------------

def test_observe_webserver():
    state = CaptureState()
    _flow(state, "10.0.0.5", 80, "203.0.113.9", 40000, bytes_sent=5000)
    behaviors = HostProfiler().observe_behaviors(state, Config(), "10.0.0.5")
    assert "acting_as_webserver" in behaviors
    assert "acting_as_scanner" not in behaviors


def test_observe_scanner_requires_multiple_ports():
    state = CaptureState()
    # 20 целей, но все на один порт 443 → браузер, не сканер.
    for i in range(20):
        _flow(state, "10.0.0.5", 40000 + i, f"203.0.113.{i + 2}", 443)
    behaviors = HostProfiler().observe_behaviors(state, Config(), "10.0.0.5")
    assert "acting_as_scanner" not in behaviors


# ---------------------------------------------------------------------
# правило: deviation / FP
# ---------------------------------------------------------------------

def _run_rule(state):
    rule = RoleDeviationRule()
    facts = rule.extract_facts(state, [], Config())
    return rule.find_contradictions(facts)


def test_workstation_as_webserver_is_critical():
    state = CaptureState()
    _host(state, "10.0.0.5", "3c:07:54:00:00:01")  # Apple workstation
    _flow(state, "10.0.0.5", 80, "203.0.113.9", 40000, bytes_sent=5000)

    contras = _run_rule(state)
    assert len(contras) == 1
    c = contras[0]
    assert c.rule == "role_deviation"
    assert c.subject == "10.0.0.5"
    assert c.severity == "critical"
    assert len(c.facts) == 2
    # Факты должны объяснять, почему workstation и почему webserver.
    preds = {f.predicate for f in c.facts}
    assert preds == {"assigned_role", "observed_behavior"}


def test_workstation_as_smb_server_is_high():
    state = CaptureState()
    _host(state, "10.0.0.5", "3c:07:54:00:00:01")
    _flow(state, "10.0.0.5", 445, "203.0.113.9", 40000, bytes_sent=5000)

    contras = _run_rule(state)
    assert len(contras) == 1
    assert contras[0].severity == "high"


def test_server_as_scanner_is_high():
    state = CaptureState()
    _host(state, "10.0.0.6", "00:0c:29:00:00:01")  # VMware server
    for i in range(20):
        _flow(
            state, "10.0.0.6", 50000 + i,
            f"10.1.0.{i + 2}", 1000 + (i % 7), bytes_sent=40,
        )

    contras = _run_rule(state)
    assert len(contras) == 1
    assert contras[0].severity == "high"
    assert contras[0].subject == "10.0.0.6"


def test_server_as_webserver_is_false_positive():
    """Сервер легитимно работает сервером — противоречия нет."""
    state = CaptureState()
    _host(state, "10.0.0.6", "00:0c:29:00:00:01")  # VMware server
    _flow(state, "10.0.0.6", 443, "203.0.113.9", 40000, bytes_sent=5000)

    assert _run_rule(state) == []


def test_unknown_role_silent():
    """Неизвестный OUI → роль unknown → правило молчит."""
    state = CaptureState()
    _host(state, "10.0.0.7", "aa:bb:cc:00:00:01")
    _flow(state, "10.0.0.7", 80, "203.0.113.9", 40000, bytes_sent=5000)

    assert _run_rule(state) == []


def test_entities_gain_role_deviation_role():
    """Сущность с role_deviation получает роль для раскраски графа."""
    from paradox.aggregators.entities import build_entities

    state = CaptureState()
    _host(state, "10.0.0.5", "3c:07:54:00:00:01")  # Apple workstation
    _flow(state, "10.0.0.5", 80, "203.0.113.9", 40000, bytes_sent=5000)

    rule = RoleDeviationRule()
    contras = rule.find_contradictions(rule.extract_facts(state, [], Config()))
    entities = build_entities(state, [], Config(), contradictions=contras)

    ent = next(e for e in entities.internal if e.ip == "10.0.0.5")
    assert "role_deviation" in ent.roles
