"""Тесты BehaviouralAnalyzer — corroboration (второе мнение).

Проверяем, что слой:
- по умолчанию молчит (behavioral_enabled=False);
- на маленьком захвате молчит (ниже behavioral_min_flows);
- НЕ создаёт новых находок, а аннотирует совпавшие rule-находки
  behavioural_score / behavioral_corroborated;
- явный выброс матчится по паре (src_ip, dst_ip) и по хосту;
- детерминирован;
- подключается через pipeline._run_behavioral.
"""
from paradox.analyzers.behavioral_analyzer import (
    BehavioralAnalyzer,
    corroborate,
)
from paradox.config import Config
from paradox.models import (
    CaptureState,
    Finding,
    FlowKey,
    FlowStats,
    packet_size_cv,
)


def _add_flow(state, proto, src, sport, dst, dport, packets, bytes_sent, ts):
    key = FlowKey(
        proto=proto, src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport,
    )
    flow = FlowStats(packets=packets, bytes_sent=bytes_sent)
    flow.first_ts = ts
    flow.last_ts = ts + 5.0
    state.flows[key] = flow


def _add_session(state, src, dst, dport, packets, bytes_out, bytes_in, ts):
    # internal → external + обратный поток
    _add_flow(state, "tcp", src, 40000, dst, dport, packets, bytes_out, ts)
    _add_flow(state, "tcp", dst, dport, src, 40000, packets, bytes_in, ts)


def _state_with_outlier():
    state = CaptureState()
    for i in range(20):
        _add_session(
            state,
            src=f"10.0.0.{i + 2}",
            dst=f"203.0.113.{i + 2}",
            dport=443,
            packets=10,
            bytes_out=1000,
            bytes_in=900,
            ts=1000.0 + i,
        )
    # Выброс: гигантский почти односторонний поток на нестандартный порт.
    _add_session(
        state,
        src="10.0.0.99",
        dst="203.0.113.99",
        dport=8443,
        packets=5000,
        bytes_out=5_000_000,
        bytes_in=50,
        ts=1000.0,
    )
    return state


def _state_with_anomalous_host():
    """10 нормальных хостов + 1 хост, обходящий 50 разных адресатов."""
    state = CaptureState()
    for i in range(10):
        src = f"10.0.0.{i + 2}"
        for j in range(2):
            _add_flow(
                state, "tcp", src, 40000,
                f"203.0.113.{i * 2 + j + 2}", 443, 10, 1000, 1000.0,
            )
    for j in range(50):
        _add_flow(
            state, "tcp", "10.0.0.99", 40000,
            f"198.51.100.{j + 2}", 443, 10, 100_000, 1000.0,
        )
    return state


def _cfg(**overrides):
    base = dict(
        behavioral_enabled=True,
        behavioral_min_flows=10,
        behavioral_min_hosts=5,
        behavioral_max_findings=10,
        behavioral_contamination=0.1,
        behavioral_confidence_min=0.7,
    )
    base.update(overrides)
    return Config(**base)


def _finding(src_ip, dst_ip, dst_port):
    return Finding(
        type="large_transfer",
        value=f"{src_ip} -> {dst_ip}:{dst_port}",
        confidence=0.85,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


# ---------------------------------------------------------------------
# packet_size_cv — общий расчёт, отданный и в детекторы
# ---------------------------------------------------------------------

def test_packet_size_cv_constant_size_is_zero():
    assert packet_size_cv(4, 400, 4 * 100 * 100) == 0.0


def test_packet_size_cv_grows_with_variance():
    # пакеты 100 и 300 байт → mean 200, std 100 → cv 0.5
    sumsq = 100 * 100 + 300 * 300
    assert abs(packet_size_cv(2, 400, sumsq) - 0.5) < 1e-9


def test_packet_size_cv_empty_flow_is_zero():
    assert packet_size_cv(0, 0, 0) == 0.0


# ---------------------------------------------------------------------
# отключение и пустые входы
# ---------------------------------------------------------------------

def test_disabled_by_default_is_noop():
    f = _finding("10.0.0.99", "203.0.113.99", 8443)
    corroborate([f], _state_with_outlier(), Config())
    assert "behavioral_corroborated" not in f.evidence


def test_below_min_flows_is_noop():
    state = CaptureState()
    _add_session(state, "10.0.0.2", "203.0.113.2", 443, 10, 1000, 900, 1000.0)
    f = _finding("10.0.0.2", "203.0.113.2", 443)
    corroborate([f], state, _cfg(behavioral_min_flows=50))
    assert "behavioral_corroborated" not in f.evidence


def test_empty_findings_is_noop():
    corroborate([], _state_with_outlier(), _cfg())


# ---------------------------------------------------------------------
# score_sessions
# ---------------------------------------------------------------------

def test_score_sessions_returns_outlier_first():
    sessions = BehavioralAnalyzer().score_sessions(
        _state_with_outlier(), _cfg(),
    )
    assert sessions
    assert sessions[0]["src_ip"] == "10.0.0.99"
    assert sessions[0]["dst_ip"] == "203.0.113.99"
    assert sessions[0]["dst_port"] == 8443
    assert all(0.0 <= s["score"] <= 1.0 for s in sessions)
    assert [s["rank"] for s in sessions] == list(
        range(1, len(sessions) + 1)
    )


# ---------------------------------------------------------------------
# host-level
# ---------------------------------------------------------------------

def test_score_hosts_disabled_by_default():
    findings = BehavioralAnalyzer().score_hosts(
        _state_with_anomalous_host(), Config(),
    )
    assert findings == []


def test_score_hosts_below_min_hosts():
    findings = BehavioralAnalyzer().score_hosts(
        _state_with_anomalous_host(), _cfg(behavioral_min_hosts=50),
    )
    assert findings == []


def test_score_hosts_flags_anomalous_host():
    findings = BehavioralAnalyzer().score_hosts(
        _state_with_anomalous_host(), _cfg(),
    )
    assert findings
    assert all(f.type == "host_behavior_anomaly" for f in findings)
    assert all(0.0 <= f.confidence <= 1.0 for f in findings)
    assert findings[0].src_ip == "10.0.0.99"
    assert findings[0].evidence["rank"] == 1
    assert "unique_dst_ips" in findings[0].evidence


# ---------------------------------------------------------------------
# corroboration
# ---------------------------------------------------------------------

def test_corroborates_matching_finding_by_pair():
    f = _finding("10.0.0.99", "203.0.113.99", 8443)
    corroborate([f], _state_with_outlier(), _cfg())
    assert f.evidence["behavioral_corroborated"] is True
    assert isinstance(f.evidence["behavioral_score"], float)


def test_corroborates_by_reverse_pair():
    # Находка ориентирована external → internal — тоже матчится.
    f = _finding("203.0.113.99", "10.0.0.99", 8443)
    corroborate([f], _state_with_outlier(), _cfg())
    assert f.evidence["behavioral_corroborated"] is True


def test_corroborates_by_host_when_dst_unknown():
    # Находка без dst_ip, но src — выброс-хост.
    f = Finding(
        type="large_transfer", value="10.0.0.99", confidence=0.85,
        src_ip="10.0.0.99",
    )
    corroborate([f], _state_with_outlier(), _cfg())
    assert f.evidence["behavioral_corroborated"] is True


def test_does_not_corroborate_normal_session():
    f = _finding("10.0.0.2", "203.0.113.2", 443)
    corroborate([f], _state_with_outlier(), _cfg())
    assert "behavioral_corroborated" not in f.evidence


def test_no_corroboration_for_different_pair_on_anomalous_host():
    # Хост 10.0.0.99 аномален, но эта пара — не выброс → не усиливаем.
    f = _finding("10.0.0.99", "8.8.8.8", 53)
    corroborate([f], _state_with_outlier(), _cfg())
    assert "behavioral_corroborated" not in f.evidence


def test_does_not_create_new_findings():
    findings = [_finding("10.0.0.2", "203.0.113.2", 443)]
    corroborate(findings, _state_with_outlier(), _cfg())
    assert len(findings) == 1


# ---------------------------------------------------------------------
# детерминизм
# ---------------------------------------------------------------------

def test_deterministic():
    state = _state_with_outlier()
    a = _finding("10.0.0.99", "203.0.113.99", 8443)
    b = _finding("10.0.0.99", "203.0.113.99", 8443)
    corroborate([a], state, _cfg())
    corroborate([b], state, _cfg())
    assert a.evidence["behavioral_score"] == b.evidence["behavioral_score"]


# ---------------------------------------------------------------------
# подключение к pipeline
# ---------------------------------------------------------------------

def test_run_behavioral_annotates_findings():
    from paradox.pipeline import _run_behavioral

    state = _state_with_outlier()
    findings = [_finding("10.0.0.99", "203.0.113.99", 8443)]
    _run_behavioral(state, _cfg(), findings)
    # corroboration на rule-находке + host-level добавляет хост-выброс.
    assert findings[0].evidence["behavioral_corroborated"] is True
    assert any(f.type == "host_behavior_anomaly" for f in findings)


def test_run_behavioral_disabled_is_noop():
    from paradox.pipeline import _run_behavioral

    state = _state_with_outlier()
    findings = [_finding("10.0.0.99", "203.0.113.99", 8443)]
    _run_behavioral(state, Config(), findings)
    assert "behavioral_corroborated" not in findings[0].evidence
