"""Tests for http_report.unique_uris (fix_23)."""
from paradox.models import CaptureState, FlowKey, FlowStats
from paradox.reporters.flow_report import build_http_report


def _state_with_n_uris(n: int) -> CaptureState:
    state = CaptureState()
    for i in range(n):
        key = FlowKey(
            proto="tcp", src_ip="10.0.0.1", dst_ip="1.1.1.1",
            src_port=10000 + i, dst_port=80,
        )
        state.flows[key] = FlowStats(
            http_method="GET",
            http_host="example.com",
            http_uri=f"/page{i}",
        )
    return state


def test_unique_uris_not_capped_by_top_n():
    """Регрессия fix_23: unique_uris = len(seen) резался top_n."""
    state = _state_with_n_uris(150)
    report = build_http_report(state, top_n=100)

    assert report["unique_uris"] == 150  # до фикса было 100


def test_unique_uris_counts_distinct_only():
    """Дубликаты (host, uri) считаются один раз."""
    state = CaptureState()
    for i in range(50):
        key = FlowKey(
            proto="tcp", src_ip="10.0.0.1", dst_ip="1.1.1.1",
            src_port=10000 + i, dst_port=80,
        )
        state.flows[key] = FlowStats(
            http_method="GET",
            http_host="example.com",
            http_uri="/same",
        )
    report = build_http_report(state, top_n=100)
    assert report["unique_uris"] == 1
