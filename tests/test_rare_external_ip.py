"""
Тесты RareExternalIPDetector.

Сценарий: внутренний клиент сходил 1–2 раза на внешний IP, которого
нет в DNS-ответах захвата. Проверяем сам сигнал и каждый фильтр,
который отделяет его от легитимных сервисов (DNS, SNI/Host,
инфраструктурные порты, поток без SYN, allowlist).
"""
from dataclasses import replace

from paradox.config import Config
from paradox.detectors.rare_external_ip import RareExternalIPDetector
from paradox.models import CaptureState, FlowKey, FlowStats

INTERNAL = "10.0.0.5"
EXTERNAL = "203.0.113.9"


def _add_flow(
    state: CaptureState,
    *,
    src_ip: str = INTERNAL,
    dst_ip: str = EXTERNAL,
    sport: int = 50000,
    dport: int = 4444,
    proto: str = "tcp",
    initiated: bool | None = True,
    sni: str | None = None,
    http_host: str | None = None,
    packets: int = 10,
    bytes_sent: int = 500,
    first: float = 1.0,
    last: float = 2.0,
) -> None:
    key = FlowKey(
        proto=proto, src_ip=src_ip, dst_ip=dst_ip,
        src_port=sport, dst_port=dport,
    )
    state.flows[key] = FlowStats(
        packets=packets,
        bytes_sent=bytes_sent,
        first_ts=first,
        last_ts=last,
        initiated_by_src=initiated,
        sni=sni,
        http_host=http_host,
    )


def _state_with_dns() -> CaptureState:
    """DNS в захвате виден, но не для нашего адреса."""
    state = CaptureState()
    state.dns_answers_by_ip["198.51.100.7"] = {"updates.example"}
    return state


def test_single_direct_connection_detected():
    state = _state_with_dns()
    _add_flow(state)

    findings = RareExternalIPDetector().run(state, Config())

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "rare_external_ip"
    assert f.value == f"{EXTERNAL}:4444"
    assert f.src_ip == INTERNAL
    assert f.dst_ip == EXTERNAL
    assert f.dst_port == 4444
    assert f.evidence["flow_count"] == 1
    assert f.evidence["resolved_by_dns"] is False


def test_two_connections_still_rare():
    state = _state_with_dns()
    _add_flow(state, sport=50000)
    _add_flow(state, sport=50001)

    findings = RareExternalIPDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 2


def test_more_than_max_connections_ignored():
    state = _state_with_dns()
    for port in (50000, 50001, 50002):
        _add_flow(state, sport=port)

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_resolved_by_dns_ignored():
    state = _state_with_dns()
    state.dns_answers_by_ip[EXTERNAL] = {"update.example"}
    _add_flow(state)

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_no_dns_at_all_means_silence():
    """Без видимого DNS нельзя утверждать, что адрес не резолвился."""
    state = CaptureState()
    _add_flow(state)

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_sni_gives_the_address_a_name():
    state = _state_with_dns()
    _add_flow(state, sni="c2.example")

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_http_host_gives_the_address_a_name():
    state = _state_with_dns()
    _add_flow(state, http_host="drop.example")

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_midstream_tcp_is_ignored():
    """Поток без SYN: DNS мог быть до начала записи."""
    state = _state_with_dns()
    _add_flow(state, initiated=None)

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_udp_without_handshake_is_allowed():
    state = _state_with_dns()
    _add_flow(state, proto="udp", initiated=None, dport=4444)

    findings = RareExternalIPDetector().run(state, Config())

    assert len(findings) == 1


def test_internal_destination_ignored():
    state = _state_with_dns()
    _add_flow(state, dst_ip="10.0.0.20")

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_infrastructure_port_ignored():
    state = _state_with_dns()
    _add_flow(state, proto="udp", initiated=None, dport=123)

    findings = RareExternalIPDetector().run(state, Config())

    assert findings == []


def test_allowlisted_ip_ignored():
    state = _state_with_dns()
    _add_flow(state)
    config = replace(
        Config(), rare_external_ip_allowlist_ips=frozenset({EXTERNAL}),
    )

    findings = RareExternalIPDetector().run(state, config)

    assert findings == []


def test_each_destination_is_its_own_finding():
    state = _state_with_dns()
    _add_flow(state, dst_ip="203.0.113.9", sport=50000)
    _add_flow(state, dst_ip="203.0.113.10", sport=50001)

    findings = RareExternalIPDetector().run(state, Config())

    assert {f.dst_ip for f in findings} == {"203.0.113.9", "203.0.113.10"}


def test_max_connections_is_configurable():
    state = _state_with_dns()
    for port in (50000, 50001, 50002):
        _add_flow(state, sport=port)
    config = replace(Config(), rare_external_ip_max_connections=3)

    findings = RareExternalIPDetector().run(state, config)

    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 3
