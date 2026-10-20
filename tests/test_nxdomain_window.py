"""Тесты nxdomain_burst с окном (v0.9.0)."""
from paradox.config import Config
from paradox.detectors.nxdomain_burst import (
    NXDOMAINBurstDetector,
    _max_in_window,
)
from paradox.models import CaptureState


# ---------- _max_in_window ----------

def test_window_empty():
    assert _max_in_window([], 60) == 0


def test_window_single():
    assert _max_in_window([100.0], 60) == 1


def test_window_all_in():
    # 5 точек в 10 секунд, окно 60 → все попадут.
    assert _max_in_window([1.0, 2.0, 5.0, 8.0, 10.0], 60) == 5


def test_window_split():
    # 3 + 2 с разрывом больше окна.
    ts = [0.0, 1.0, 2.0, 100.0, 101.0]
    assert _max_in_window(ts, 60) == 3


def test_window_exact_boundary():
    # ts[right] - ts[left] == 60 → включается.
    ts = [0.0, 30.0, 60.0]
    assert _max_in_window(ts, 60) == 3


def test_window_just_over_boundary():
    # 60.001 → выпадает левая.
    ts = [0.0, 30.0, 60.001]
    assert _max_in_window(ts, 60) == 2


def test_window_sliding_shift():
    # Окно "сдвигается": 3 точки в [100,160], ещё 3 в [150,210].
    # Максимум в [150,210] = 4 (150,160,200,210).
    ts = [100.0, 140.0, 160.0, 200.0, 210.0]
    # 100,140,160 → 3. 140,160,200 → 3. 160,200,210 → 3.
    assert _max_in_window(ts, 60) == 3


# ---------- detector: windowing ----------

def _state(src, ts_list):
    state = CaptureState()
    state.dns_nxdomain_by_src[src] = len(ts_list)
    state.dns_nxdomain_ts_by_src[src] = list(ts_list)
    return state


def test_no_burst_spread_over_hour():
    """100 NXDOMAIN, но разбросаны по часу — не burst."""
    ts = [float(i) for i in range(0, 3600, 36)]  # 100 точек / 1 час
    state = _state("192.168.1.10", ts)
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert findings == []


def test_burst_inside_window():
    """10 NXDOMAIN за 30 секунд — burst."""
    ts = [100.0, 102.0, 105.0, 108.0, 110.0,
          115.0, 120.0, 125.0, 128.0, 130.0]
    state = _state("192.168.1.10", ts)
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "nxdomain_burst"
    assert f.src_ip == "192.168.1.10"
    assert f.evidence["max_in_window"] == 10
    assert f.evidence["windowed"] is True
    assert f.confidence == 0.9


def test_below_threshold_in_window():
    """4 в окне при threshold=5 — не срабатывает."""
    ts = [100.0, 110.0, 120.0, 130.0]
    state = _state("192.168.1.10", ts)
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert findings == []


def test_two_bursts_apart():
    """Два бурста по 5, но в разных окнах → один finding (max=5)."""
    ts = [100.0, 105.0, 110.0, 115.0, 120.0,   # burst 1
          500.0, 505.0, 510.0, 515.0, 520.0]   # burst 2
    state = _state("192.168.1.10", ts)
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["max_in_window"] == 5
    assert findings[0].evidence["nxdomain_count"] == 10


# ---------- detector: backward compat (без ts) ----------

def test_backward_compat_no_ts():
    """Старое поведение: есть count, нет ts → finding с windowed=False."""
    state = CaptureState()
    state.dns_nxdomain_by_src["192.168.1.10"] = 10
    # ts не задаём — как в старых тестах.
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["windowed"] is False
    assert findings[0].evidence["nxdomain_count"] == 10


def test_backward_compat_below_threshold():
    state = CaptureState()
    state.dns_nxdomain_by_src["192.168.1.10"] = 3  # < 5
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert findings == []


# ---------- multiple srcs ----------

def test_multiple_srcs_isolated():
    state = CaptureState()
    # src A: burst
    state.dns_nxdomain_by_src["A"] = 10
    state.dns_nxdomain_ts_by_src["A"] = [1.0, 2.0, 3.0, 4.0, 5.0,
                                          6.0, 7.0, 8.0, 9.0, 10.0]
    # src B: размазано
    state.dns_nxdomain_by_src["B"] = 10
    state.dns_nxdomain_ts_by_src["B"] = [float(i * 500) for i in range(10)]
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].src_ip == "A"


def test_empty_state():
    findings = NXDOMAINBurstDetector().run(CaptureState(), Config())
    assert findings == []


# ---------- v0.9.0: ratio-фильтр ----------

def test_ratio_filter_drops_noise():
    """6 NXDOMAIN в окне, но 5000 успешных запросов → шум."""
    state = CaptureState()
    state.dns_nxdomain_by_src["A"] = 6
    state.dns_nxdomain_ts_by_src["A"] = [100.0 + i for i in range(6)]
    # 5000 успешных запросов.
    state.dns_queries_by_src["A"] = {f"ok{i}.com": 1 for i in range(5000)}
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert findings == []


def test_ratio_filter_keeps_burst():
    """10 NXDOMAIN в окне, 15 всех DNS → 0.67 — burst."""
    state = CaptureState()
    state.dns_nxdomain_by_src["A"] = 10
    state.dns_nxdomain_ts_by_src["A"] = [100.0 + i for i in range(10)]
    state.dns_queries_by_src["A"] = {f"q{i}.com": 1 for i in range(15)}
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["ratio"] >= 0.2


def test_ratio_exactly_at_threshold():
    """Ровно 0.2 → проходит (>=(min_ratio))."""
    state = CaptureState()
    state.dns_nxdomain_by_src["A"] = 10
    state.dns_nxdomain_ts_by_src["A"] = [100.0 + i for i in range(10)]
    # 50 всего → 10/50 = 0.2
    state.dns_queries_by_src["A"] = {f"q{i}.com": 1 for i in range(40)}
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1


def test_ratio_below_threshold():
    """19 NXDOMAIN при 200 успешных → 19/200 = 0.095 < 0.2 → отсекается."""
    state = CaptureState()
    state.dns_nxdomain_by_src["A"] = 19
    state.dns_nxdomain_ts_by_src["A"] = [100.0 + i for i in range(19)]
    state.dns_queries_by_src["A"] = {f"q{i}.com": 1 for i in range(200)}
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert findings == []


def test_ratio_no_query_data():
    """Нет dns_queries_by_src → fallback ratio=1.0, не отсекаем."""
    state = CaptureState()
    state.dns_nxdomain_by_src["A"] = 10
    state.dns_nxdomain_ts_by_src["A"] = [100.0 + i for i in range(10)]
    # dns_queries_by_src не заполняем.
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["ratio"] == 1.0
