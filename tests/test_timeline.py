"""
Тесты timeline / kill-chain reconstruction.

Проверяем:
  - детерминированность и сортировку build_timeline
  - маппинг тип finding → фаза
  - маппинг rule contradiction → фаза
  - edge cases (пустой вход, отсутствие ts, пустые facts)
  - summarize_by_phase

v0.8.0: timeline tests
"""
from paradox.contradictions.base import Contradiction, Fact
from paradox.models import Finding
from paradox.timeline import (
    build_timeline,
    summarize_by_phase,
)

# ---------- helpers ----------

def _f(ftype, ts, src="1.1.1.1", dst="2.2.2.2", **kw):
    return Finding(
        type=ftype, value="v", confidence=kw.pop("confidence", 0.8),
        src_ip=src, dst_ip=dst,
        first_seen=ts,
        severity=kw.pop("severity", "medium"),
        mitre_techniques=kw.pop("mitre_techniques", ()),
        **kw,
    )


def _c(rule, subject, facts_ts, severity="critical", confidence=0.8):
    facts = [
        Fact(
            source="finding", subject=subject,
            predicate="victim_of", value="x",
            ts=ts, confidence=0.8, evidence={},
        )
        for ts in facts_ts
    ]
    return Contradiction(
        rule=rule, subject=subject, facts=facts,
        severity=severity, confidence=confidence,
        likely_causes=[], resolution_hint=None,
    )


# ---------- пустой вход ----------

def test_empty_findings_empty_timeline():
    assert build_timeline([]) == []


def test_empty_with_none_contradictions():
    assert build_timeline([], None) == []


def test_empty_with_empty_contradictions():
    assert build_timeline([], []) == []


# ---------- finding без first_seen ----------

def test_finding_without_ts_skipped():
    f = Finding(type="brute_force", value="v", confidence=0.8)
    assert build_timeline([f]) == []


def test_mixed_some_without_ts():
    f1 = _f("brute_force", 100.0)
    f2 = Finding(type="port_scan", value="v", confidence=0.7)  # без ts
    f3 = _f("beaconing", 200.0)
    events = build_timeline([f1, f2, f3])
    assert len(events) == 2
    assert {e.type for e in events} == {"brute_force", "beaconing"}


# ---------- фазы ----------

def test_phase_recon():
    events = build_timeline([_f("port_scan", 1.0)])
    assert events[0].phase == "recon"
    assert events[0].chain_order == 10


def test_phase_initial_access():
    events = build_timeline([_f("brute_force", 1.0)])
    assert events[0].phase == "initial_access"
    assert events[0].chain_order == 20


def test_phase_execution():
    events = build_timeline([_f("command_injection", 1.0)])
    assert events[0].phase == "execution"
    assert events[0].chain_order == 30


def test_phase_c2():
    events = build_timeline([_f("beaconing", 1.0)])
    assert events[0].phase == "c2"
    assert events[0].chain_order == 60


def test_phase_lateral_movement():
    events = build_timeline([_f("lateral_movement", 1.0)])
    assert events[0].phase == "lateral_movement"
    assert events[0].chain_order == 50


def test_phase_exfiltration():
    events = build_timeline([_f("large_transfer", 1.0)])
    assert events[0].phase == "exfiltration"
    assert events[0].chain_order == 70


def test_unknown_type_goes_to_other():
    events = build_timeline([_f("totally_new_type", 1.0)])
    assert events[0].phase == "other"
    assert events[0].chain_order == 999


# ---------- сортировка ----------

def test_sorted_by_ts():
    events = build_timeline([
        _f("beaconing", 300.0),
        _f("port_scan", 100.0),
        _f("brute_force", 200.0),
    ])
    assert [e.ts for e in events] == [100.0, 200.0, 300.0]


def test_same_ts_sorted_by_chain_order():
    # Один ts, разные фазы. recon (10) → c2 (60).
    events = build_timeline([
        _f("beaconing", 100.0, src="b"),
        _f("port_scan", 100.0, src="a"),
    ])
    assert events[0].type == "port_scan"
    assert events[1].type == "beaconing"


def test_same_ts_same_order_sorted_by_subject():
    # port_scan и web_scanner — обе recon (10), разные subject.
    events = build_timeline([
        _f("web_scanner", 100.0, src="z"),
        _f("port_scan", 100.0, src="a"),
    ])
    assert events[0].subject == "a"
    assert events[1].subject == "z"


def test_deterministic_order():
    """Одинаковый вход — одинаковый выход (несколько раз)."""
    findings = [
        _f("beaconing", 300.0, src="z"),
        _f("port_scan", 100.0, src="a"),
        _f("brute_force", 100.0, src="a"),
        _f("lateral_movement", 200.0, src="m"),
    ]
    runs = [build_timeline(findings) for _ in range(3)]
    sigs = [[(e.ts, e.type, e.subject) for e in r] for r in runs]
    assert sigs[0] == sigs[1] == sigs[2]


# ---------- contradictions ----------

def test_contradiction_event_ts_from_max_facts():
    c = _c("victim_makes_attack", "9.9.9.9", [10.0, 42.0, 20.0])
    events = build_timeline([], [c])
    assert len(events) == 1
    assert events[0].ts == 42.0
    assert events[0].kind == "contradiction"
    assert events[0].type == "victim_makes_attack"
    assert events[0].phase == "lateral_movement"
    assert events[0].chain_order == 50


def test_contradiction_without_facts_skipped():
    c = _c("mac_ip_conflict", "1.1.1.1", [])
    assert build_timeline([], [c]) == []


def test_contradiction_zero_ts_skipped():
    # Все facts с ts=0 → событие пропускается.
    c = _c("mac_ip_conflict", "1.1.1.1", [0.0, 0.0])
    assert build_timeline([], [c]) == []


def test_contradiction_phase_mac_ip_conflict():
    c = _c("mac_ip_conflict", "1.1.1.1", [10.0])
    events = build_timeline([], [c])
    assert events[0].phase == "initial_access"


def test_contradiction_phase_reverse_asymmetry():
    c = _c("reverse_asymmetry", "1.1.1.1", [10.0])
    events = build_timeline([], [c])
    assert events[0].phase == "exfiltration"


def test_unknown_rule_goes_to_other():
    c = _c("brand_new_rule", "1.1.1.1", [10.0])
    events = build_timeline([], [c])
    assert events[0].phase == "other"
    assert events[0].chain_order == 999


# ---------- смешанный вход ----------

def test_mixed_findings_and_contradictions():
    f = _f("brute_force", 100.0)
    c = _c("victim_makes_attack", "1.1.1.1", [150.0])
    events = build_timeline([f], [c])
    assert len(events) == 2
    assert events[0].kind == "finding"
    assert events[1].kind == "contradiction"
    assert [e.ts for e in events] == [100.0, 150.0]


# ---------- summarize_by_phase ----------

def test_summarize_empty():
    assert summarize_by_phase([]) == []


def test_summarize_groups_and_orders():
    events = build_timeline([
        _f("port_scan", 1.0),          # recon
        _f("brute_force", 2.0),        # initial_access
        _f("command_injection", 3.0),  # execution
        _f("large_transfer", 4.0),     # exfiltration
    ])
    grouped = summarize_by_phase(events)
    phases = [g["phase"] for g in grouped]
    assert phases == ["recon", "initial_access", "execution", "exfiltration"]
    for g in grouped:
        assert g["count"] == 1
        assert isinstance(g["events"], list)
        assert len(g["events"]) == g["count"]


def test_summarize_groups_multiple_events():
    events = build_timeline([
        _f("port_scan", 1.0, src="a"),
        _f("web_scanner", 2.0, src="b"),
        _f("beaconing", 3.0),
    ])
    grouped = summarize_by_phase(events)
    by_phase = {g["phase"]: g for g in grouped}
    assert by_phase["recon"]["count"] == 2
    assert by_phase["c2"]["count"] == 1


def test_summarize_unknown_at_end():
    events = build_timeline([
        _f("unknown_type", 1.0),
        _f("port_scan", 2.0),
    ])
    grouped = summarize_by_phase(events)
    # other (999) идёт после recon (10).
    assert grouped[0]["phase"] == "recon"
    assert grouped[-1]["phase"] == "other"


# ---------- to_dict ----------

def test_event_to_dict_keys():
    events = build_timeline([_f("port_scan", 1.0)])
    d = events[0].to_dict()
    for key in (
        "ts", "kind", "type", "subject", "severity",
        "confidence", "phase", "chain_order",
        "description", "mitre_id", "ref_id",
    ):
        assert key in d, f"missing {key}"


def test_event_carries_mitre_id():
    f = _f("command_injection", 1.0, mitre_techniques=("T1190", "T1059"))
    events = build_timeline([f])
    assert events[0].mitre_id == "T1190"


def test_event_no_mitre_when_empty():
    f = _f("brand_new", 1.0)
    events = build_timeline([f])
    assert events[0].mitre_id is None


# ---------- subject из src_ip ----------

def test_subject_uses_src_ip():
    f = _f("port_scan", 1.0, src="10.0.0.5")
    events = build_timeline([f])
    assert events[0].subject == "10.0.0.5"


def test_subject_empty_when_no_src():
    f = Finding(
        type="port_scan", value="v", confidence=0.7,
        first_seen=1.0,  # без src_ip
    )
    events = build_timeline([f])
    assert events[0].subject == ""


# ---------- v0.9.0: carved_file в timeline ----------

class _Carved:
    """Заглушка CarvedFile для тестов."""
    def __init__(self, ts, uri="a.sh", size=100, ext=".sh",
                 sha256="deadbeef" * 8, dst_ip="192.168.1.1"):
        self.first_ts = ts
        self.uri = uri
        self.size = size
        self.ext = ext
        self.sha256 = sha256
        self.dst_ip = dst_ip


def test_carved_file_event_created():
    cf = _Carved(ts=100.0, uri="/payload.sh")
    events = build_timeline([], [], carved_files=[cf])
    assert len(events) == 1
    e = events[0]
    assert e.kind == "carved_file"
    assert e.type == "carved_file"
    assert e.phase == "execution"
    assert e.chain_order == 30
    assert e.mitre_id == "T1105"
    assert "/payload.sh" in e.description


def test_carved_file_no_ts_skipped():
    cf = _Carved(ts=None)
    events = build_timeline([], [], carved_files=[cf])
    assert events == []


def test_carved_file_zero_ts_skipped():
    cf = _Carved(ts=0.0)
    events = build_timeline([], [], carved_files=[cf])
    assert events == []


def test_carved_file_mixed_with_findings():
    f = _f("brute_force", 50.0, src="10.0.0.1")
    cf = _Carved(ts=100.0, uri="/x.ps1")
    events = build_timeline([f], [], carved_files=[cf])
    assert len(events) == 2
    assert events[0].ts == 50.0
    assert events[1].ts == 100.0
    assert events[1].kind == "carved_file"


def test_carved_file_backward_compat_no_arg():
    """build_timeline(findings, contradictions) без carved_files — ок."""
    f = _f("port_scan", 10.0)
    events = build_timeline([f], [])
    assert len(events) == 1
