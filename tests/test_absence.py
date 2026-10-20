"""Тесты Absence analysis."""
from paradox.analyzers.absence import analyze_absence
from paradox.models import CaptureState, FlowKey, FlowStats


def test_absence_empty():
    state = CaptureState()
    res = analyze_absence(state)
    assert res["dns_unanswered"] == []
    assert res["tcp_unanswered"] == []


def test_absence_dns_unanswered():
    state = CaptureState()
    state.dns_queries["bad.com"] = 5
    state.dns_queries["good.com"] = 1
    state.dns_answers_by_name["good.com"] = {"1.2.3.4"}

    res = analyze_absence(state)
    assert len(res["dns_unanswered"]) == 1
    assert res["dns_unanswered"][0]["qname"] == "bad.com"
    assert res["dns_unanswered"][0]["count"] == 5


def test_absence_tcp_unanswered():
    state = CaptureState()
    # Клиент (10.0.0.1) -> Сервер (10.0.0.2:80)
    k1 = FlowKey(proto="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=80)
    state.flows[k1] = FlowStats(packets=1, initiated_by_src=True)

    # Нет обратного потока (10.0.0.2:80 -> 10.0.0.1:12345)

    res = analyze_absence(state)
    assert len(res["tcp_unanswered"]) == 1
    assert res["tcp_unanswered"][0]["src_ip"] == "10.0.0.1"
    assert res["tcp_unanswered"][0]["dst_ip"] == "10.0.0.2"


def test_absence_tcp_answered():
    state = CaptureState()
    k1 = FlowKey(proto="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=80)
    k2 = FlowKey(proto="tcp", src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=12345)
    state.flows[k1] = FlowStats(packets=1, initiated_by_src=True)
    state.flows[k2] = FlowStats(packets=1, initiated_by_src=False)

    res = analyze_absence(state)
    assert len(res["tcp_unanswered"]) == 0
