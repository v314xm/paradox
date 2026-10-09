"""
Регрессионные тесты на FP из реального датасета FIRST-2015.

Каждый тест привязан к конкретному домену, который был FP,
и к фиксу, который его закрыл. Если регрессия вернётся —
тест упадёт.

Не путать с test_detectors.py — там базовое поведение детекторов.
Здесь только «вот этот домен не должен ловиться».
"""
from pcap_triage.config import Config
from pcap_triage.detectors.dga import DGADetector
from pcap_triage.detectors.typosquatting import TyposquattingDetector
from pcap_triage.models import CaptureState


def _state_with_dns(*domains):
    """CaptureState с заполненным dns_queries. Один домен = 1 запрос."""
    state = CaptureState()
    for d in domains:
        state.dns_queries[d] = 1
    return state


# ---------- Typosquatting: SLD-only ----------

def test_typosquatting_googleads_doubleclick_not_flagged():
    """googleads — поддомен doubleclick, SLD=doubleclick, не google."""
    findings = TyposquattingDetector().run(
        _state_with_dns("googleads.g.doubleclick.net"), Config(),
    )
    assert findings == []


def test_typosquatting_googleads4_doubleclick_not_flagged():
    findings = TyposquattingDetector().run(
        _state_with_dns("googleads4.g.doubleclick.net"), Config(),
    )
    assert findings == []


def test_typosquatting_app_loadimpact_not_flagged():
    """app.loadimpact.com — SLD loadimpact, не apple."""
    findings = TyposquattingDetector().run(
        _state_with_dns("app.loadimpact.com"), Config(),
    )
    assert findings == []


def test_typosquatting_app_webinspector_not_flagged():
    findings = TyposquattingDetector().run(
        _state_with_dns("app.webinspector.com"), Config(),
    )
    assert findings == []


def test_typosquatting_google_analytics_not_flagged():
    findings = TyposquattingDetector().run(
        _state_with_dns("google-analytics.com"), Config(),
    )
    assert findings == []


def test_typosquatting_googlecode_not_flagged():
    findings = TyposquattingDetector().run(
        _state_with_dns("google-code-prettify.googlecode.com"), Config(),
    )
    assert findings == []


# ---------- Typosquatting: sub-brand / tracking ----------

def test_typosquatting_microsoftstore_not_flagged():
    """microsoftstore.com — sub-brand, brand в начале SLD."""
    findings = TyposquattingDetector().run(
        _state_with_dns("www.microsoftstore.com"), Config(),
    )
    assert findings == []


def test_typosquatting_s_microsoft_not_flagged():
    """s-microsoft.com — tracking CDN Microsoft."""
    findings = TyposquattingDetector().run(
        _state_with_dns("i.s-microsoft.com"), Config(),
    )
    assert findings == []


def test_typosquatting_paypalobjects_not_flagged():
    findings = TyposquattingDetector().run(
        _state_with_dns("www.paypalobjects.com"), Config(),
    )
    assert findings == []


def test_typosquatting_googletagservices_not_flagged():
    findings = TyposquattingDetector().run(
        _state_with_dns("www.googletagservices.com"), Config(),
    )
    assert findings == []


def test_typosquatting_amazon_adsystem_not_flagged():
    findings = TyposquattingDetector().run(
        _state_with_dns("c.amazon-adsystem.com"), Config(),
    )
    assert findings == []


def test_typosquatting_appier_not_flagged():
    """appier vs apple — разные концы слова."""
    findings = TyposquattingDetector().run(
        _state_with_dns("rcp.c.appier.net"), Config(),
    )
    assert findings == []


def test_typosquatting_behance_not_flagged():
    """behance vs binance — lev=2, ratio 2/7=0.29 > 0.25."""
    findings = TyposquattingDetector().run(
        _state_with_dns("www.behance.net"), Config(),
    )
    assert findings == []


# ---------- Typosquatting: реальные typosquats всё ещё ловятся ----------

def test_typosquatting_still_detects_contains_typosquat():
    """event-datamicrosoft.live — brand в середине SLD, реальный typosquat."""
    findings = TyposquattingDetector().run(
        _state_with_dns("event-datamicrosoft.live"), Config(),
    )
    assert len(findings) == 1
    assert findings[0].evidence["kind"] == "contains"


def test_typosquatting_still_detects_levenshtein_typosquat():
    """micr0soft.com — SLD micr0soft, lev=1."""
    findings = TyposquattingDetector().run(
        _state_with_dns("micr0soft.com"), Config(),
    )
    assert len(findings) == 1
    assert findings[0].evidence["kind"] == "levenshtein"


# ---------- DGA ----------

def test_dga_stackoverflow_not_flagged():
    findings = DGADetector().run(
        _state_with_dns("stackoverflow.com"), Config(),
    )
    assert findings == []


def test_dga_serverfault_not_flagged():
    findings = DGADetector().run(
        _state_with_dns("serverfault.com"), Config(),
    )
    assert findings == []


def test_dga_pwned_se_still_flagged():
    """pwned.se DGA-поддомены — реальный сигнал, не должен пропасть."""
    findings = DGADetector().run(
        _state_with_dns("dackrpbfnmwjl.pwned.se"), Config(),
    )
    assert len(findings) == 1
    assert findings[0].value == "dackrpbfnmwjl.pwned.se"


# ---------- PortScanDetector ----------

def test_port_scan_detects_one_src_many_dsts():
    """Один src, много dst на один порт → один port_scan finding."""
    from pcap_triage.detectors.port_scan import PortScanDetector
    from pcap_triage.models import FlowKey, FlowStats

    state = CaptureState()
    for i in range(15):
        key = FlowKey(
            proto="tcp",
            src_ip="192.168.0.53", dst_ip=f"203.0.113.{i}",
            src_port=50000 + i, dst_port=8080,
        )
        state.flows[key] = FlowStats(packets=1, bytes_sent=62)

    findings = PortScanDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "port_scan"
    assert findings[0].evidence["distinct_dsts"] == 15
    assert findings[0].evidence["dst_port"] == 8080


def test_port_scan_below_threshold():
    """9 dst — меньше порога 10, не скан."""
    from pcap_triage.detectors.port_scan import PortScanDetector
    from pcap_triage.models import FlowKey, FlowStats

    state = CaptureState()
    for i in range(9):
        key = FlowKey(
            proto="tcp",
            src_ip="192.168.0.53", dst_ip=f"203.0.113.{i}",
            src_port=50000 + i, dst_port=8080,
        )
        state.flows[key] = FlowStats(packets=1, bytes_sent=62)

    findings = PortScanDetector().run(state, Config())
    assert findings == []


def test_port_scan_ignores_browser_like_traffic():
    """Много flow'ов к каждому dst — не скан, а браузер."""
    from pcap_triage.detectors.port_scan import PortScanDetector
    from pcap_triage.models import FlowKey, FlowStats

    state = CaptureState()
    for i in range(15):
        for j in range(10):
            key = FlowKey(
                proto="tcp",
                src_ip="192.168.0.53", dst_ip=f"203.0.113.{i}",
                src_port=50000 + i * 10 + j, dst_port=443,
            )
            state.flows[key] = FlowStats(packets=20, bytes_sent=5000)

    findings = PortScanDetector().run(state, Config())
    assert findings == []


# ---------- LateralMovementDetector ----------

def _lm_state(flows):
    """flows: list of (src, dst, dport, ua, uri)."""
    from pcap_triage.models import FlowKey, FlowStats
    state = CaptureState()
    for i, (src, dst, dport, ua, uri) in enumerate(flows):
        key = FlowKey(
            proto="tcp", src_ip=src, dst_ip=dst,
            src_port=40000 + i, dst_port=dport,
        )
        fs = FlowStats(packets=5, bytes_sent=500)
        fs.http_user_agent = ua
        fs.http_uri = uri
        state.flows[key] = fs
    return state


def test_lateral_movement_winrm_ruby_ua():
    """Ruby WinRM Client на 5985 — точно lateral movement, score 0.8."""
    from pcap_triage.detectors.lateral_movement import LateralMovementDetector
    state = _lm_state([
        ("192.168.1.12", "192.168.1.1", 5985,
         "Ruby WinRM Client (2.8.3, ruby 3.3.7)", "/wsman"),
    ])
    findings = LateralMovementDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].type == "lateral_movement"
    assert findings[0].confidence == 0.8
    assert "user_agent" in findings[0].evidence["match_reasons"]


def test_lateral_movement_smb_internal_many_flows():
    """5+ flows на 445 internal → internal, score 0.6."""
    from pcap_triage.detectors.lateral_movement import LateralMovementDetector
    state = _lm_state([
        ("10.0.1.50", "192.168.1.12", 445, None, None),
        ("10.0.1.50", "192.168.1.12", 445, None, None),
        ("10.0.1.50", "192.168.1.12", 445, None, None),
        ("10.0.1.50", "192.168.1.12", 445, None, None),
        ("10.0.1.50", "192.168.1.12", 445, None, None),
    ])
    findings = LateralMovementDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].confidence == 0.6
    assert findings[0].evidence["match_reasons"] == ["port"]


def test_lateral_movement_single_rdp_not_flagged():
    """Один RDP-сеанс к jump-host — норма, не finding."""
    from pcap_triage.detectors.lateral_movement import LateralMovementDetector
    state = _lm_state([
        ("192.168.0.1", "192.168.0.51", 3389, None, None),
    ])
    findings = LateralMovementDetector().run(state, Config())
    assert findings == []


def test_lateral_movement_external_src_not_flagged():
    """Внешний src на 445 — это не lateral movement (другой детектор)."""
    from pcap_triage.detectors.lateral_movement import LateralMovementDetector
    state = _lm_state([
        ("203.0.113.5", "192.168.1.12", 445, None, None),
    ])
    findings = LateralMovementDetector().run(state, Config())
    assert findings == []


def test_lateral_movement_admin_allowlist():
    """Allowlist: jump-host не флагуется."""
    from pcap_triage.detectors.lateral_movement import LateralMovementDetector
    from dataclasses import replace
    config = replace(
        Config(),
        lateral_movement_admin_srcs=frozenset({"10.0.1.50"}),
    )
    state = _lm_state([
        ("10.0.1.50", "192.168.1.12", 445, None, None),
    ])
    findings = LateralMovementDetector().run(state, config)
    assert findings == []


def test_lateral_movement_aggregates_flows():
    """3 flow к одному (src, dst, dport) → один finding."""
    from pcap_triage.detectors.lateral_movement import LateralMovementDetector
    state = _lm_state([
        ("10.0.1.50", "192.168.1.12", 5985,
         "Ruby WinRM Client", "/wsman"),
        ("10.0.1.50", "192.168.1.12", 5985,
         "Ruby WinRM Client", "/wsman"),
        ("10.0.1.50", "192.168.1.12", 5985,
         "Ruby WinRM Client", "/wsman"),
    ])
    findings = LateralMovementDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 3


# ---------- LargeTransferDetector ----------

def test_large_transfer_detects_single_huge_flow():
    """123 MB в одном flow — finding."""
    from pcap_triage.detectors.large_transfer import LargeTransferDetector
    from pcap_triage.models import FlowKey, FlowStats

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="80.64.102.71", dst_ip="192.168.1.1",
        src_port=443, dst_port=53427,
    )
    fs = FlowStats(packets=57845, bytes_sent=123 * 1024 * 1024)
    fs.sni = "salam-spbsed-ras-d83.rtbcdn.ru"
    state.flows[key] = fs

    findings = LargeTransferDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].type == "large_transfer"
    assert findings[0].evidence["total_bytes"] >= 100 * 1024 * 1024


def test_large_transfer_below_threshold():
    """10 MB — не finding."""
    from pcap_triage.detectors.large_transfer import LargeTransferDetector
    from pcap_triage.models import FlowKey, FlowStats

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.1", dst_ip="8.8.8.8",
        src_port=50000, dst_port=443,
    )
    state.flows[key] = FlowStats(packets=5000, bytes_sent=10 * 1024 * 1024)

    findings = LargeTransferDetector().run(state, Config())
    assert findings == []


def test_large_transfer_pair_sums_both_directions():
    """Прямой 60 MB + обратный 50 MB = 110 MB > 100 MB."""
    from pcap_triage.detectors.large_transfer import LargeTransferDetector
    from pcap_triage.models import FlowKey, FlowStats

    state = CaptureState()
    fwd = FlowKey(
        proto="tcp",
        src_ip="80.64.102.71", dst_ip="192.168.1.1",
        src_port=443, dst_port=53427,
    )
    rev = FlowKey(
        proto="tcp",
        src_ip="192.168.1.1", dst_ip="80.64.102.71",
        src_port=53427, dst_port=443,
    )
    state.flows[fwd] = FlowStats(packets=30000, bytes_sent=60 * 1024 * 1024)
    state.flows[rev] = FlowStats(packets=25000, bytes_sent=50 * 1024 * 1024)

    findings = LargeTransferDetector().run(state, Config())
    assert len(findings) == 1
    assert findings[0].evidence["total_bytes"] >= 110 * 1024 * 1024
    assert findings[0].evidence["flow_count"] == 2