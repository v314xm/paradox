import time

import pytest

pytestmark = pytest.mark.slow
from paradox.config import Config
from paradox.detectors.beaconing import BeaconingDetector
from paradox.detectors.port_scan import PortScanDetector
from paradox.models import CaptureState, FlowKey, FlowStats


@pytest.fixture
def config():
    return Config()


def test_port_scan_perf(config):
    det = PortScanDetector()
    state = CaptureState()

    # 10 000 уникальных соединений (симуляция агрессивного скана)
    for i in range(10000):
        key = FlowKey("tcp", "10.0.0.5", f"192.168.{i // 256}.{i % 256}", 12345, 443)
        state.flows[key] = FlowStats(packets=1)

    t0 = time.perf_counter()
    det.run(state, config)
    elapsed = time.perf_counter() - t0

    print(f"\nPortScan 10k flows: {elapsed:.3f} сек")
    assert elapsed < 3.0, f"Слишком медленно: {elapsed:.3f} сек"


def test_beaconing_perf(config):
    det = BeaconingDetector()
    state = CaptureState()

    # 50 000 flows (симуляция долгого C2-канала)
    for i in range(50000):
        key = FlowKey("tcp", "10.0.0.5", "8.8.8.8", 10000 + (i % 1000), 443)
        state.flows[key] = FlowStats(packets=2, bytes_sent=100, first_ts=float(i), last_ts=float(i + 0.5))

    t0 = time.perf_counter()
    det.run(state, config)
    elapsed = time.perf_counter() - t0

    print(f"\nBeaconing 50k flows: {elapsed:.3f} сек")
    assert elapsed < 3.0, f"Слишком медленно: {elapsed:.3f} сек"
