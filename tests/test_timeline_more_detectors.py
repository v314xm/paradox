"""Timeline получает smtp_spam, ip_check_service, nxdomain_burst (fix_28)."""
from paradox.config import Config
from paradox.detectors.ip_check_service import IPCheckServiceDetector
from paradox.detectors.nxdomain_burst import NXDOMAINBurstDetector
from paradox.detectors.smtp_spam import SMTP_SpamDetector
from paradox.models import CaptureState, FlowKey, FlowStats


def _flow(src, dst, dport, first, last, src_port=40000, **kwargs):
    key = FlowKey(
        proto="tcp", src_ip=src, dst_ip=dst,
        src_port=src_port, dst_port=dport,
    )
    return key, FlowStats(first_ts=first, last_ts=last, **kwargs)


def test_smtp_spam_has_timestamps():
    state = CaptureState()
    state.smtp_rcpt_by_src["10.0.0.5"] = {
        f"victim{i}@example.com" for i in range(50)
    }
    for i in range(3):
        key, flow = _flow(
            "10.0.0.5", "1.2.3.4", 25,
            100.0 + i, 100.5 + i, src_port=40000 + i,
        )
        state.flows[key] = flow
    findings = SMTP_SpamDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].first_seen == 100.0
    assert findings[0].last_seen == 102.5


def test_ip_check_service_has_timestamps():
    state = CaptureState()
    key, flow = _flow(
        "10.0.0.5", "208.95.112.1", 443, 200.0, 200.5,
    )
    flow.sni = "ip-api.com"
    state.flows[key] = flow
    findings = IPCheckServiceDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].first_seen == 200.0
    assert findings[0].last_seen == 200.5


def test_nxdomain_burst_has_timestamps():
    state = CaptureState()
    state.dns_nxdomain_by_src["10.0.0.5"] = 10
    state.dns_nxdomain_ts_by_src["10.0.0.5"] = [
        100.0 + i for i in range(10)
    ]
    state.dns_queries_by_src["10.0.0.5"] = {
        f"bad{i}.dga.com": 1 for i in range(10)
    }
    findings = NXDOMAINBurstDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].first_seen == 100.0
    assert findings[0].last_seen == 109.0
