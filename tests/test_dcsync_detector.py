"""DCSyncDetector: opnum 3 в DRSUAPI-контексте."""
from paradox.config import Config
from paradox.detectors.dcsync import DCSyncDetector
from paradox.models import CaptureState
from paradox.taxonomy import get_techniques


def test_dcsync_flags_getncchanges():
    state = CaptureState()
    state.dcerpc_drsuapi_calls[("10.0.0.5", "10.0.0.10", 445, 3)] = 2
    state.dcerpc_naming_contexts[
        ("10.0.0.5", "10.0.0.10", "DC=corp,DC=local")
    ] = 1

    findings = DCSyncDetector().run(state, Config())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "dcsync"
    assert finding.severity == "critical"
    assert finding.confidence == 0.7
    assert finding.src_ip == "10.0.0.5"
    assert finding.dst_ip == "10.0.0.10"
    assert finding.dst_port == 445
    assert "DC=corp,DC=local" in finding.value
    assert finding.evidence["calls"] == 2
    assert finding.evidence["naming_contexts"] == ["DC=corp,DC=local"]


def test_dcsync_silent_without_opnum_three():
    state = CaptureState()
    state.dcerpc_drsuapi_calls[("10.0.0.5", "10.0.0.10", 445, 0)] = 1
    state.dcerpc_drsuapi_calls[("10.0.0.5", "10.0.0.10", 445, 4)] = 1

    assert DCSyncDetector().run(state, Config()) == []


def test_dcsync_silent_on_empty_state():
    assert DCSyncDetector().run(CaptureState(), Config()) == []


def test_dcsync_separates_pairs():
    state = CaptureState()
    state.dcerpc_drsuapi_calls[("10.0.0.5", "10.0.0.10", 445, 3)] = 1
    state.dcerpc_drsuapi_calls[("10.0.0.6", "10.0.0.10", 135, 3)] = 1

    findings = DCSyncDetector().run(state, Config())

    assert [(f.src_ip, f.dst_port) for f in findings] == [
        ("10.0.0.5", 445),
        ("10.0.0.6", 135),
    ]


def test_dcsync_taxonomy():
    assert get_techniques("dcsync") == ("T1003.006",)
