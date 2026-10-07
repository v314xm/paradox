"""
Unit-тесты BruteForceDetector.

Работаем с CaptureState руками. Проверяем:
- детект при 20+ flows с уникальными src_ports,
- игнор при <20 flows,
- игнор длинной сессии (много пакетов на flow),
- игнор port scan (разные dst_port, по 1 flow),
- кастомные пороги через Config,
- агрегацию (несколько dst_port — разные findings).
"""
from pcap_triage.config import Config
from pcap_triage.detectors.brute_force import BruteForceDetector
from pcap_triage.models import CaptureState, FlowKey, FlowStats


def _add_flow(state, src_ip, dst_ip, sport, dport,
              packets=1, bytes_sent=100, ts=1.0):
    key = FlowKey(proto="tcp", src_ip=src_ip, dst_ip=dst_ip,
                  src_port=sport, dst_port=dport)
    state.flows[key] = FlowStats(
        packets=packets, bytes_sent=bytes_sent,
        first_ts=ts, last_ts=ts,
    )


# ---------- основной сценарий ----------

def test_brute_force_detected():
    """230 flows с уникальными src_ports к одной цели → finding."""
    state = CaptureState()
    for i in range(230):
        _add_flow(
            state,
            "10.0.1.50", "192.168.1.12", 50000 + i, 80,
            packets=2, bytes_sent=200,
        )

    findings = BruteForceDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "brute_force"
    assert findings[0].value == "10.0.1.50 -> 192.168.1.12:80"
    assert findings[0].evidence["flow_count"] == 230
    assert findings[0].evidence["unique_src_ports"] == 230
    assert findings[0].confidence >= 0.9


# ---------- ниже порога ----------

def test_below_min_flows():
    """5 flows — меньше порога (20), не finding."""
    state = CaptureState()
    for i in range(5):
        _add_flow(
            state,
            "10.0.1.50", "192.168.1.12", 50000 + i, 80,
            packets=2,
        )

    findings = BruteForceDetector().run(state, Config())

    assert findings == []


# ---------- длинная сессия ----------

def test_long_session_not_detected():
    """Один flow с 300 пакетами — не brute force (это сессия)."""
    state = CaptureState()
    _add_flow(
        state,
        "10.0.1.247", "192.168.1.12", 39566, 22,
        packets=331, bytes_sent=300894,
    )

    findings = BruteForceDetector().run(state, Config())

    assert findings == []


def test_long_sessions_multiple_flows_not_detected():
    """20 flows, но avg_packets > 20 — не brute force."""
    state = CaptureState()
    for i in range(20):
        _add_flow(
            state,
            "10.0.1.50", "192.168.1.12", 50000 + i, 80,
            packets=50,  # avg_packets = 50 > 20 (порог)
        )

    findings = BruteForceDetector().run(state, Config())

    assert findings == []


# ---------- port scan ----------

def test_port_scan_not_detected():
    """100 flows к РАЗНЫМ dst_port по 1 flow — это scan, не brute force."""
    state = CaptureState()
    for i in range(100):
        _add_flow(
            state,
            "10.0.1.50", "192.168.1.12", 50000 + i, 1000 + i,
            packets=2,
        )

    findings = BruteForceDetector().run(state, Config())

    # каждая пара (src, dst, dst_port) имеет 1 flow — ниже порога
    assert findings == []


# ---------- кастомные пороги ----------

def test_custom_thresholds():
    """Понижаем min_flows до 5 → срабатывает на 5 flow'ах."""
    state = CaptureState()
    for i in range(5):
        _add_flow(
            state,
            "10.0.1.50", "192.168.1.12", 50000 + i, 80,
            packets=2,
        )

    config = Config()
    config.brute_force_min_flows = 5
    config.brute_force_min_unique_src_ports = 3

    findings = BruteForceDetector().run(state, config)

    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 5


# ---------- агрегация по нескольким целям ----------

def test_separate_targets_give_separate_findings():
    """Два разных dst_port — два отдельных finding'а."""
    state = CaptureState()

    for i in range(30):
        _add_flow(state, "10.0.1.50", "192.168.1.12", 50000 + i, 80, packets=2)
    for i in range(30):
        _add_flow(state, "10.0.1.50", "192.168.1.12", 60000 + i, 21, packets=2)

    findings = BruteForceDetector().run(state, Config())

    assert len(findings) == 2
    values = sorted(f.value for f in findings)
    assert values == [
        "10.0.1.50 -> 192.168.1.12:21",
        "10.0.1.50 -> 192.168.1.12:80",
    ]


# ---------- игнор udp / без порта ----------

def test_udp_ignored():
    """UDP flows не участвуют в brute-force — только TCP."""
    state = CaptureState()
    for i in range(50):
        key = FlowKey(proto="udp", src_ip="10.0.1.50",
                      dst_ip="192.168.1.12", src_port=50000 + i, dst_port=53)
        state.flows[key] = FlowStats(packets=1, bytes_sent=50,
                                     first_ts=1.0, last_ts=1.0)

    findings = BruteForceDetector().run(state, Config())

    assert findings == []


def test_flow_without_dst_port_ignored():
    """Flow без dst_port (например, other-протокол) — пропускается."""
    state = CaptureState()
    for i in range(50):
        key = FlowKey(proto="other", src_ip="10.0.1.50",
                      dst_ip="192.168.1.12", src_port=None, dst_port=None)
        state.flows[key] = FlowStats(packets=1, bytes_sent=50,
                                     first_ts=1.0, last_ts=1.0)

    findings = BruteForceDetector().run(state, Config())

    assert findings == []