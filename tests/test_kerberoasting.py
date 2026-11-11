"""Kerberoasting: RC4 и перечисление сервисных SPN."""
from paradox.config import Config
from paradox.detectors.kerberoasting import KerberoastingDetector
from paradox.models import CaptureState

CLIENT = "10.0.0.5"
KDC = "10.0.0.1"


def _state(spns: dict[str, int], etypes: dict[int, int]) -> CaptureState:
    state = CaptureState()
    for spn, count in spns.items():
        state.kerberos_tgs_requests[(CLIENT, KDC, spn)] = count
    for etype, count in etypes.items():
        state.kerberos_etypes[(CLIENT, KDC, etype)] = count
    return state


def test_rc4_service_ticket_is_high():
    state = _state({"MSSQLSvc/db.corp.local:1433": 1}, {23: 1})

    findings = KerberoastingDetector().run(state, Config())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "kerberoasting"
    assert finding.severity == "high"
    assert finding.src_ip == CLIENT
    assert finding.dst_ip == KDC
    assert finding.dst_port == 88
    assert finding.evidence["rc4_requests"] == 1
    assert finding.evidence["spns"] == ["MSSQLSvc/db.corp.local:1433"]


def test_five_spn_without_rc4_is_medium():
    spns = {f"HTTP/svc{i}.corp.local": 1 for i in range(5)}
    state = _state(spns, {18: 5})

    findings = KerberoastingDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].evidence["distinct_spns"] == 5


def test_three_spn_without_rc4_is_low():
    spns = {f"HTTP/svc{i}.corp.local": 1 for i in range(3)}
    state = _state(spns, {18: 3})

    findings = KerberoastingDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_single_spn_without_rc4_is_normal_access():
    state = _state({"HTTP/intranet.corp.local": 1}, {18: 1})

    assert KerberoastingDetector().run(state, Config()) == []


def test_no_kerberos_no_findings():
    assert KerberoastingDetector().run(CaptureState(), Config()) == []
