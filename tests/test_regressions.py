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
        for j in range(10):   # 10 flow'ов к каждому dst
            key = FlowKey(
                proto="tcp",
                src_ip="192.168.0.53", dst_ip=f"203.0.113.{i}",
                src_port=50000 + i * 10 + j, dst_port=443,
            )
            state.flows[key] = FlowStats(packets=20, bytes_sent=5000)

    findings = PortScanDetector().run(state, Config())
    assert findings == []