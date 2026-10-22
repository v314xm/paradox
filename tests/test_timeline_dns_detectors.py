"""dga/cloud_tunnel/typosquatting получают timestamps (fix_31)."""
from paradox.config import Config
from paradox.detectors.cloud_tunnel import CloudTunnelDetector
from paradox.detectors.dga import DGADetector
from paradox.detectors.typosquatting import TyposquattingDetector
from paradox.models import CaptureState
from paradox.timeline import build_timeline


def test_dga_has_timestamps():
    state = CaptureState()
    state.dns_queries["xg7f2k9vbnqwerty.com"] = 1
    state.dns_query_ts_by_name["xg7f2k9vbnqwerty.com"] = [100.0, 200.0]
    findings = DGADetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].first_seen == 100.0
    assert findings[0].last_seen == 200.0

    events = build_timeline(findings)
    assert len(events) == 1
    assert events[0].phase == "c2"


def test_cloud_tunnel_has_timestamps():
    state = CaptureState()
    state.dns_queries["evil.trycloudflare.com"] = 1
    state.dns_query_ts_by_name["evil.trycloudflare.com"] = [50.0, 60.0]
    findings = CloudTunnelDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].first_seen == 50.0
    assert findings[0].last_seen == 60.0


def test_typosquatting_has_timestamps():
    # micros0ft: lev=1 (0→o), ratio 1/9 < 0.25 — проходит фильтр.
    # g00gle: lev=2, ratio 2/6 = 0.33 > 0.25 — детектор его режет.
    state = CaptureState()
    state.dns_queries["micros0ft.com"] = 1
    state.dns_query_ts_by_name["micros0ft.com"] = [30.0, 40.0]
    findings = TyposquattingDetector().run(state, Config())
    typo = [f for f in findings if f.value == "micros0ft.com"]
    assert len(typo) == 1
    assert typo[0].first_seen == 30.0
    assert typo[0].last_seen == 40.0
