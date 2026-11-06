"""
Тесты summary-разреза по протоколам (by_l4 / by_l7).

Разрез считается по flows и попадает в report["summary"]["protocols"].
"""
from paradox.config import Config
from paradox.models import CaptureState, FlowKey, FlowStats
from paradox.pipeline import _summarize_protocols


def _add(state, proto, sport, dport, **flow_fields):
    key = FlowKey(
        proto=proto, src_ip="10.0.0.10", dst_ip="10.0.0.20",
        src_port=sport, dst_port=dport,
    )
    flow = FlowStats(packets=1, bytes_sent=100)
    flow.first_ts = 1.0
    flow.last_ts = 2.0
    for name, value in flow_fields.items():
        setattr(flow, name, value)
    state.flows[key] = flow


def test_protocol_summary_classifies_l7_by_facts():
    state = CaptureState()
    _add(state, "tcp", 50000, 443, sni="example.com")
    _add(state, "tcp", 50001, 80, http_host="example.com")
    _add(state, "udp", 50002, 53)
    _add(state, "tcp", 50003, 445)
    _add(state, "icmp", None, None)

    summary = _summarize_protocols(state, Config())

    assert summary["by_l7"]["tls"] == 1
    assert summary["by_l7"]["http"] == 1
    assert summary["by_l7"]["dns"] == 1
    assert summary["by_l7"]["smb"] == 1
    assert summary["by_l7"]["icmp"] == 1
    assert summary["by_l4"]["tcp"] == 3
    assert summary["by_l4"]["udp"] == 1
    assert summary["by_l4"]["icmp"] == 1


def test_protocol_summary_response_flow_classified_by_src_port():
    """Обратный flow: 443 в src_port, эфемерный в dst_port — всё равно tls."""
    state = CaptureState()
    _add(state, "tcp", 443, 52527)
    summary = _summarize_protocols(state, Config())
    assert summary["by_l7"] == {"tls": 1}


def test_protocol_summary_unknown_port_is_other():
    state = CaptureState()
    _add(state, "udp", 50000, 9999)
    summary = _summarize_protocols(state, Config())
    assert summary["by_l7"] == {"other": 1}


def test_protocol_summary_sorted_by_count_desc():
    state = CaptureState()
    _add(state, "udp", 50000, 9999)
    _add(state, "udp", 50001, 9998)
    _add(state, "tcp", 50002, 443)

    summary = _summarize_protocols(state, Config())

    assert list(summary["by_l4"]) == ["udp", "tcp"]
    assert list(summary["by_l7"]) == ["other", "tls"]


def test_protocol_summary_empty_state():
    assert _summarize_protocols(CaptureState(), Config()) == {
        "by_l4": {},
        "by_l7": {},
    }
