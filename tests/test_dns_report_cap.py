"""DNS-секция отчёта не должна быть неограниченной."""
from paradox.models import CaptureState
from paradox.reporters.flow_report import build_dns_report


def test_nxdomain_list_is_capped_but_totals_remain():
    state = CaptureState()
    state.dns_queries["ok.example"] = 3
    state.dns_nxdomain["a.example"] = 5
    state.dns_nxdomain["b.example"] = 1
    state.dns_nxdomain["c.example"] = 2

    report = build_dns_report(state, top_n=2)

    assert [d["name"] for d in report["nxdomain"]] == [
        "a.example", "c.example",
    ]
    assert report["nxdomain_unique"] == 3
    assert report["nxdomain_total"] == 8
