import pytest

from paradox.config import Config
from paradox.detectors.dga import DGADetector
from paradox.detectors.large_transfer import LargeTransferDetector
from paradox.models import CaptureState, FlowKey, FlowStats


@pytest.fixture
def config():
    return Config()


def test_large_transfer_windows_update_fp(config):
    """Windows Update не должен считаться утечкой."""
    det = LargeTransferDetector()
    state = CaptureState()

    key = FlowKey("tcp", "192.168.1.10", "13.107.4.50", 12345, 443)
    flow = FlowStats()
    flow.bytes_sent = 150 * 1024 * 1024  # 150 МБ
    flow.http_host = "download.microsoft.com"
    flow.http_user_agent = "Microsoft BITS/7.8"
    state.flows[key] = flow

    findings = det.run(state, config)
    assert len(findings) == 0, "Large transfer сработал на Windows Update (FP)"


def test_dga_allowlist_fp(config):
    """Легитимные CDN с длинными именами не должны триггерить DGA."""
    det = DGADetector()
    state = CaptureState()

    state.dns_queries["d3js8k5g2m9x8v.cloudfront.net"] = 1
    state.dns_queries["secure-connect-12345.amazonaws.com"] = 1

    findings = det.run(state, config)
    assert len(findings) == 0, "DGA сработал на легитимный CDN (FP)"