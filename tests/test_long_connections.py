"""
Тесты LongConnectionDetector.

Сигнал: долгая TCP-сессия наружу без SNI/Host на неслужебном порту.
Проверяем, что правило ловит keepalive-сессию и молчит на всех
штатных случаях: короткая сессия, внутренний обмен, именованный
push-канал, служебный порт, поток без SYN, UDP.
"""
from dataclasses import replace

from paradox.config import Config
from paradox.detectors.long_connections import LongConnectionDetector
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
    duration: float = 3600.0,
    packets: int = 10,
    bytes_sent: int = 500,
    sni: str | None = None,
    http_host: str | None = None,
) -> None:
    key = FlowKey(
        proto=proto, src_ip=src_ip, dst_ip=dst_ip,
        src_port=sport, dst_port=dport,
    )
    state.flows[key] = FlowStats(
        packets=packets,
        bytes_sent=bytes_sent,
        first_ts=1000.0,
        last_ts=1000.0 + duration,
        initiated_by_src=initiated,
        sni=sni,
        http_host=http_host,
    )


def test_long_unnamed_session_detected():
    state = CaptureState()
    _add_flow(state)

    findings = LongConnectionDetector().run(state, Config())

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "long_connection"
    assert f.value == f"{INTERNAL} -> {EXTERNAL}:4444"
    assert f.src_ip == INTERNAL
    assert f.dst_ip == EXTERNAL
    assert f.dst_port == 4444
    assert f.evidence["duration_min"] == 60.0


def test_short_session_ignored():
    state = CaptureState()
    _add_flow(state, duration=600.0)

    assert LongConnectionDetector().run(state, Config()) == []


def test_internal_destination_ignored():
    state = CaptureState()
    _add_flow(state, dst_ip="10.0.0.20")

    assert LongConnectionDetector().run(state, Config()) == []


def test_inbound_session_ignored():
    state = CaptureState()
    _add_flow(state, src_ip=EXTERNAL, dst_ip=INTERNAL)

    assert LongConnectionDetector().run(state, Config()) == []


def test_midstream_session_ignored():
    state = CaptureState()
    _add_flow(state, initiated=None)

    assert LongConnectionDetector().run(state, Config()) == []


def test_udp_flow_ignored():
    """У UDP длительность — горизонт захвата, а не жизнь сессии."""
    state = CaptureState()
    _add_flow(state, proto="udp", initiated=None)

    assert LongConnectionDetector().run(state, Config()) == []


def test_allowlisted_sni_ignored():
    state = CaptureState()
    _add_flow(state, dport=443, sni="client.wns.windows.com")

    assert LongConnectionDetector().run(state, Config()) == []


def test_allowlisted_http_host_ignored():
    state = CaptureState()
    _add_flow(state, dport=80, http_host="update.microsoft.com")

    assert LongConnectionDetector().run(state, Config()) == []


def test_unknown_name_still_detected():
    """Имя не из allowlist — сессия всё равно интересна."""
    state = CaptureState()
    _add_flow(state, dport=443, sni="c2.example")

    findings = LongConnectionDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].evidence["sni"] == "c2.example"


def test_excluded_port_ignored():
    state = CaptureState()
    _add_flow(state, dport=22)

    assert LongConnectionDetector().run(state, Config()) == []


def test_too_few_packets_ignored():
    """SYN и тишина полчаса — не сессия, а полуоткрытое соединение."""
    state = CaptureState()
    _add_flow(state, packets=2)

    assert LongConnectionDetector().run(state, Config()) == []


def test_duration_threshold_is_configurable():
    state = CaptureState()
    _add_flow(state, duration=600.0)
    config = replace(Config(), long_connection_min_duration_sec=300)

    findings = LongConnectionDetector().run(state, config)

    assert len(findings) == 1
    assert findings[0].evidence["duration_min"] == 10.0
