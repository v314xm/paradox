"""Timeline получает port_scan findings с timestamps (fix_27)."""
from paradox.config import Config
from paradox.detectors.port_scan import PortScanDetector
from paradox.models import CaptureState, FlowKey, FlowStats
from paradox.timeline import build_timeline


def test_port_scan_has_timestamps():
    """Регрессия: без first_seen/last_seen timeline пропускал port_scan."""
    state = CaptureState()
    for i in range(20):
        key = FlowKey(
            proto="tcp", src_ip="10.0.0.1",
            dst_ip=f"1.1.1.{i + 1}", src_port=40000 + i, dst_port=22,
        )
        state.flows[key] = FlowStats(
            first_ts=1000.0 + i, last_ts=1001.0 + i,
        )
    findings = PortScanDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].first_seen == 1000.0
    assert findings[0].last_seen == 1020.0

    events = build_timeline(findings)
    assert len(events) == 1
    assert events[0].phase == "recon"
    assert events[0].type == "port_scan"


def test_port_scan_without_ts_still_works():
    """Если у flows нет timestamps — finding создаётся, но с None."""
    state = CaptureState()
    for i in range(20):
        key = FlowKey(
            proto="tcp", src_ip="10.0.0.1",
            dst_ip=f"1.1.1.{i + 1}", src_port=40000 + i, dst_port=22,
        )
        state.flows[key] = FlowStats()  # без first_ts/last_ts
    findings = PortScanDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None

    # Timeline такое пропускает — ожидаемое поведение.
    events = build_timeline(findings)
    assert len(events) == 0
