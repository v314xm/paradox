"""Тесты JA3S Malware Detector.

Детектор по умолчанию молчит (ja3s_known_malware = {}), поэтому
все тесты переопределяют Config через dataclasses.replace.
"""
import types
from dataclasses import replace

from paradox.config import Config
from paradox.detectors.ja3s_malware import JA3SMalwareDetector
from paradox.models import CaptureState, FlowKey, FlowStats


def _cfg(hashes: dict[str, str]) -> Config:
    return replace(Config(), ja3s_known_malware=types.MappingProxyType(hashes))


def _flow(sport=50000, ja3s="cafe" * 8):
    fs = FlowStats(packets=10, bytes_sent=1000, first_ts=100.0, last_ts=200.0)
    fs.ja3s = ja3s
    return fs


def test_empty_state():
    assert JA3SMalwareDetector().run(CaptureState(), Config()) == []


def test_default_config_silent():
    """Пустой ja3s_known_malware — детектор молчит, даже если flow есть."""
    state = CaptureState()
    key = FlowKey("tcp", "1.1.1.1", "2.2.2.2", 50000, 443)
    state.flows[key] = _flow()
    assert JA3SMalwareDetector().run(state, Config()) == []


def test_matches_known():
    cfg = _cfg({"cafe" * 8: "TestServer"})
    state = CaptureState()
    key = FlowKey("tcp", "1.1.1.1", "2.2.2.2", 50000, 443)
    state.flows[key] = _flow()
    findings = JA3SMalwareDetector().run(state, cfg)
    assert len(findings) == 1
    assert findings[0].type == "ja3s_malware"
    assert findings[0].evidence["tool_name"] == "TestServer"


def test_aggregates_by_ja3s():
    cfg = _cfg({"cafe" * 8: "TestServer"})
    state = CaptureState()
    for i in range(3):
        key = FlowKey("tcp", "1.1.1.1", "2.2.2.2", 50000 + i, 443)
        state.flows[key] = _flow(sport=50000 + i)
    findings = JA3SMalwareDetector().run(state, cfg)
    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 3


def test_unknown_ja3s_not_flagged():
    cfg = _cfg({"cafe" * 8: "TestServer"})
    state = CaptureState()
    key = FlowKey("tcp", "1.1.1.1", "2.2.2.2", 50000, 443)
    state.flows[key] = _flow(ja3s="0" * 32)
    assert JA3SMalwareDetector().run(state, cfg) == []


def test_flow_without_ja3s_ignored():
    cfg = _cfg({"cafe" * 8: "TestServer"})
    state = CaptureState()
    key = FlowKey("tcp", "1.1.1.1", "2.2.2.2", 50000, 443)
    fs = FlowStats(packets=10, bytes_sent=1000)
    fs.ja3s = None
    state.flows[key] = fs
    assert JA3SMalwareDetector().run(state, cfg) == []


def test_timestamps_and_evidence():
    cfg = _cfg({"cafe" * 8: "TestServer"})
    state = CaptureState()
    key = FlowKey("tcp", "1.1.1.1", "2.2.2.2", 50000, 443)
    state.flows[key] = _flow()
    findings = JA3SMalwareDetector().run(state, cfg)
    f = findings[0]
    assert f.first_seen == 100.0
    assert f.last_seen == 200.0
    assert f.evidence["dst_ports"] == [443]
    assert f.evidence["top_src_ips"][0]["ip"] == "1.1.1.1"
