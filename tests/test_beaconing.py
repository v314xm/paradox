"""
Тесты BeaconingDetector.

Проверяем:
- периодические соединения → finding
- нерегулярные → нет
- мало соединений → нет
- большие соединения → нет (это не heartbeat, а загрузка)

Плюс регрессии на будущее — если что-то поедет в алгоритме.
"""
from pcap_triage.config import Config
from pcap_triage.detectors.beaconing import BeaconingDetector
from pcap_triage.models import CaptureState, FlowKey, FlowStats


def _beacon_state(flows):
    """flows: list of (src, dst, dport, sport, first_ts, packets, bytes)."""
    state = CaptureState()
    for (src, dst, dport, sport, ts, pkts, byts) in flows:
        key = FlowKey(
            proto="tcp", src_ip=src, dst_ip=dst,
            src_port=sport, dst_port=dport,
        )
        fs = FlowStats(packets=pkts, bytes_sent=byts)
        fs.first_ts = ts
        fs.last_ts = ts + 1.0
        state.flows[key] = fs
    return state


def test_beaconing_detects_periodic():
    """20 соединений с интервалом 60 сек — типичный C2 heartbeat."""
    flows = [
        ("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 60.0, 5, 500)
        for i in range(20)
    ]
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].type == "beaconing"
    assert findings[0].evidence["count"] == 20
    assert findings[0].confidence > 0.7
    assert findings[0].evidence["mean_interval_sec"] == 60.0


def test_beaconing_ignores_irregular():
    """Те же 20 соединений, но с большим jitter — это не beacon."""
    flows = []
    ts = 1000.0
    for i in range(20):
        ts += 30.0 if i % 2 == 0 else 230.0
        flows.append(("192.168.1.100", "203.0.113.5", 443, 50000 + i, ts, 5, 500))
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_below_min_connections():
    """5 соединений — меньше порога 10."""
    flows = [
        ("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 60.0, 5, 500)
        for i in range(5)
    ]
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_ignores_large_transfers():
    """Регулярные соединения, но с большим объёмом — не heartbeat."""
    flows = [
        ("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 60.0, 100, 500_000)
        for i in range(20)
    ]
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_below_min_duration():
    """10 соединений за 5 минут — меньше порога длительности 300 сек."""
    flows = [
        ("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 30.0, 5, 500)
        for i in range(10)
    ]
    # duration = 9 * 30 = 270 сек < 300 → не finding
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_confidence_scales_with_jitter():
    """Меньше jitter — выше confidence."""
    # Идеальный интервал 60.0
    flows_perfect = [
        ("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 60.0, 5, 500)
        for i in range(20)
    ]
    # Небольшой jitter ±5
    flows_jitter = []
    for i in range(20):
        offset = 5.0 if i % 2 == 0 else -5.0
        flows_jitter.append(
            ("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 60.0 + offset, 5, 500)
        )

    findings_perfect = BeaconingDetector().run(_beacon_state(flows_perfect), Config())
    findings_jitter = BeaconingDetector().run(_beacon_state(flows_jitter), Config())

    assert len(findings_perfect) == 1
    assert len(findings_jitter) == 1
    assert findings_perfect[0].confidence > findings_jitter[0].confidence


def test_beaconing_aggregates_by_flow_key():
    """Разные src_ports, но один (src_ip, dst_ip, dst_port) — один group."""
    flows = [
        ("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 60.0, 5, 500)
        for i in range(15)
    ]
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["count"] == 15


def test_beaconing_separate_targets():
    """Два разных dst → два finding'а."""
    flows = []
    for i in range(15):
        flows.append(("192.168.1.100", "203.0.113.5", 443, 50000 + i, 1000.0 + i * 60.0, 5, 500))
    for i in range(15):
        flows.append(("192.168.1.100", "203.0.113.6", 443, 60000 + i, 1000.0 + i * 60.0, 5, 500))
    state = _beacon_state(flows)
    findings = BeaconingDetector().run(state, Config())
    assert len(findings) == 2
    values = sorted(f.value for f in findings)
    assert values == ["192.168.1.100 -> 203.0.113.5:443", "192.168.1.100 -> 203.0.113.6:443"]


def test_beaconing_ignores_udp():
    """UDP не считается — beaconing на TCP."""
    from pcap_triage.models import FlowKey, FlowStats
    state = CaptureState()
    for i in range(15):
        key = FlowKey(
            proto="udp", src_ip="192.168.1.100", dst_ip="203.0.113.5",
            src_port=50000 + i, dst_port=53,
        )
        fs = FlowStats(packets=2, bytes_sent=100)
        fs.first_ts = 1000.0 + i * 60.0
        fs.last_ts = fs.first_ts + 0.5
        state.flows[key] = fs
    findings = BeaconingDetector().run(state, Config())
    assert findings == []


def test_beaconing_empty_state():
    """Пустой CaptureState — не падает."""
    findings = BeaconingDetector().run(CaptureState(), Config())
    assert findings == []