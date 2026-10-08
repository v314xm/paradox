"""
Unit-тесты детекторов.

Без scapy, без pcap — только CaptureState руками.
Это принципиально: детектор — чистая функция над CaptureState,
и его поведение можно проверить за миллисекунды.

Запуск:
    pytest tests/ -v
"""

from pcap_triage.config import Config
from pcap_triage.detectors.cloud_tunnel import CloudTunnelDetector
from pcap_triage.detectors.dga import DGADetector
from pcap_triage.detectors.ip_check_service import IPCheckServiceDetector
from pcap_triage.detectors.nxdomain_burst import NXDOMAINBurstDetector
from pcap_triage.detectors.sni_mismatch import SNIMismatchDetector
from pcap_triage.detectors.suspicious_port import SuspiciousPortDetector
from pcap_triage.detectors.typosquatting import TyposquattingDetector
from pcap_triage.detectors.typosquatting import levenshtein
from pcap_triage.models import CaptureState, FlowKey, FlowStats


# ---------- DGADetector ----------

def test_dga_detects_high_entropy_domain():
    state = CaptureState()
    state.dns_queries["kq3jf9zxqp1mwv7n.ru"] = 5

    findings = DGADetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "dga_domain"
    assert findings[0].value == "kq3jf9zxqp1mwv7n.ru"
    assert findings[0].confidence > 0.6


def test_dga_ignores_normal_domain():
    state = CaptureState()
    state.dns_queries["google.com"] = 10

    findings = DGADetector().run(state, Config())

    assert findings == []


def test_dga_ignores_allowlisted_domain():
    state = CaptureState()
    state.dns_queries["some-long-random-name.amazonaws.com"] = 1

    findings = DGADetector().run(state, Config())

    assert findings == []


def test_dga_ignores_cloud_tunnel_domain():
    """Регрессия: cloud tunnel поддомены не должны ловиться как DGA."""
    state = CaptureState()
    state.dns_queries["varying-rentals-calgary-predict.trycloudflare.com"] = 1

    findings = DGADetector().run(state, Config())

    assert findings == []


def test_dga_ignores_short_label():
    state = CaptureState()
    state.dns_queries["xk3j.ru"] = 1

    findings = DGADetector().run(state, Config())

    assert findings == []


def test_dga_ignores_label_with_hyphen():
    """Регрессия с реального pcap: safebrowsing-cache.google.com
    не должен ловиться как DGA, несмотря на высокую энтропию."""
    state = CaptureState()
    state.dns_queries["safebrowsing-cache.google.com"] = 294

    findings = DGADetector().run(state, Config())

    assert findings == []


def test_dga_still_detects_no_hyphen_dga():
    """Гипотетический DGA без дефисов всё ещё ловится."""
    state = CaptureState()
    state.dns_queries["kq3jf9zxqp1mwv7n.ru"] = 1

    findings = DGADetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "dga_domain"


# ---------- SuspiciousPortDetector ----------

def test_suspicious_port_detects_external_4444():
    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.100", dst_ip="203.0.113.66",
        src_port=53000, dst_port=4444,
    )
    state.flows[key] = FlowStats(packets=3, bytes_sent=180)

    findings = SuspiciousPortDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "suspicious_port"
    assert findings[0].value == "203.0.113.66:4444"
    assert findings[0].evidence["flow_count"] == 1


def test_suspicious_port_ignores_internal():
    """474 flow'а к 192.168.1.12:21 — это внутренний FTP, не сигнал."""
    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="192.168.0.5", dst_ip="192.168.1.12",
        src_port=54000, dst_port=21,
    )
    state.flows[key] = FlowStats(packets=3, bytes_sent=180)

    findings = SuspiciousPortDetector().run(state, Config())

    assert findings == []


def test_suspicious_port_ignores_normal_port():
    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.100", dst_ip="142.250.185.78",
        src_port=52000, dst_port=443,
    )
    state.flows[key] = FlowStats(packets=3, bytes_sent=120)

    findings = SuspiciousPortDetector().run(state, Config())

    assert findings == []


def test_suspicious_port_ignores_no_port():
    state = CaptureState()
    key = FlowKey(
        proto="other",
        src_ip="192.168.1.100", dst_ip="203.0.113.66",
        src_port=None, dst_port=None,
    )
    state.flows[key] = FlowStats(packets=1, bytes_sent=60)

    findings = SuspiciousPortDetector().run(state, Config())

    assert findings == []


def test_suspicious_port_aggregates_same_dst():
    """Много flow'ов к одной паре dst_ip:dst_port → один finding."""
    state = CaptureState()
    for sport in (54000, 54001, 54002):
        key = FlowKey(
            proto="tcp",
            src_ip="192.168.1.100", dst_ip="203.0.113.66",
            src_port=sport, dst_port=4444,
        )
        state.flows[key] = FlowStats(packets=2, bytes_sent=100)

    findings = SuspiciousPortDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].value == "203.0.113.66:4444"
    assert findings[0].evidence["flow_count"] == 3


def test_suspicious_port_separate_dst():
    """Разные dst_ip → разные findings."""
    state = CaptureState()
    for dst in ("203.0.113.66", "203.0.113.77"):
        key = FlowKey(
            proto="tcp",
            src_ip="192.168.1.100", dst_ip=dst,
            src_port=54000, dst_port=4444,
        )
        state.flows[key] = FlowStats(packets=2, bytes_sent=100)

    findings = SuspiciousPortDetector().run(state, Config())

    assert len(findings) == 2
    values = sorted(f.value for f in findings)
    assert values == ["203.0.113.66:4444", "203.0.113.77:4444"]


# ---------- NXDOMAINBurstDetector ----------

def test_nxdomain_burst_detects():
    state = CaptureState()
    state.dns_nxdomain_by_src["192.168.1.100"] = 6

    findings = NXDOMAINBurstDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "nxdomain_burst"
    assert findings[0].value == "192.168.1.100"
    assert findings[0].evidence["nxdomain_count"] == 6


def test_nxdomain_burst_below_threshold():
    state = CaptureState()
    state.dns_nxdomain_by_src["192.168.1.100"] = 4

    findings = NXDOMAINBurstDetector().run(state, Config())

    assert findings == []


def test_nxdomain_burst_exactly_threshold():
    state = CaptureState()
    state.dns_nxdomain_by_src["192.168.1.100"] = 5

    findings = NXDOMAINBurstDetector().run(state, Config())

    assert len(findings) == 1


# ---------- CloudTunnelDetector ----------

def test_cloud_tunnel_detects_trycloudflare():
    state = CaptureState()
    state.dns_queries["abc.trycloudflare.com"] = 2

    findings = CloudTunnelDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "cloud_tunnel_domain"
    assert findings[0].value == "abc.trycloudflare.com"
    assert findings[0].evidence["matched_suffix"] == "trycloudflare.com"


def test_cloud_tunnel_detects_ngrok():
    state = CaptureState()
    state.dns_queries["abc123.ngrok.io"] = 1

    findings = CloudTunnelDetector().run(state, Config())

    assert len(findings) == 1


def test_cloud_tunnel_ignores_normal():
    state = CaptureState()
    state.dns_queries["google.com"] = 5

    findings = CloudTunnelDetector().run(state, Config())

    assert findings == []


def test_cloud_tunnel_does_not_match_partial_suffix():
    """fake-trycloudflare.com не должен матчиться."""
    state = CaptureState()
    state.dns_queries["fake-trycloudflare.com"] = 1

    findings = CloudTunnelDetector().run(state, Config())

    assert findings == []


# ---------- IPCheckServiceDetector ----------

def test_ip_check_service_detects():
    state = CaptureState()
    state.dns_queries["ip-api.com"] = 1

    findings = IPCheckServiceDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "ip_check_service"
    assert findings[0].value == "ip-api.com"


def test_ip_check_service_ignores_subdomain():
    state = CaptureState()
    state.dns_queries["some.random.ip-api.com"] = 1

    findings = IPCheckServiceDetector().run(state, Config())

    assert findings == []


def test_ip_check_service_ignores_normal():
    state = CaptureState()
    state.dns_queries["google.com"] = 10

    findings = IPCheckServiceDetector().run(state, Config())

    assert findings == []


# ---------- TyposquattingDetector ----------

def test_typosquatting_detects_contains():
    state = CaptureState()
    state.dns_queries["event-datamicrosoft.live"] = 1

    findings = TyposquattingDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "typosquatting"
    assert findings[0].evidence["kind"] == "contains"
    assert findings[0].evidence["brand"] == "microsoft"


def test_typosquatting_detects_levenshtein():
    state = CaptureState()
    state.dns_queries["micr0soft.com"] = 1

    findings = TyposquattingDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].evidence["kind"] == "levenshtein"
    assert findings[0].evidence["brand"] == "microsoft"


def test_typosquatting_ignores_legitimate_brand_domain():
    state = CaptureState()
    state.dns_queries["microsoft.com"] = 1

    findings = TyposquattingDetector().run(state, Config())

    assert findings == []


def test_typosquatting_ignores_legitimate_subdomain():
    state = CaptureState()
    state.dns_queries["update.microsoft.com"] = 1

    findings = TyposquattingDetector().run(state, Config())

    assert findings == []


def test_typosquatting_ignores_unrelated_domain():
    state = CaptureState()
    state.dns_queries["stackoverflow.com"] = 1

    findings = TyposquattingDetector().run(state, Config())

    assert findings == []


def test_levenshtein_basic():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("microsoft", "microsoft") == 0
    assert levenshtein("micr0soft", "microsoft") == 1
    assert levenshtein("", "abc") == 3


# ---------- SNIMismatchDetector ----------

def test_sni_mismatch_detects_sni_not_in_dns():
    """SNI есть, но домен не резолвился через DNS — подозрительно."""
    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.100", dst_ip="203.0.113.66",
        src_port=54000, dst_port=443,
    )
    state.flows[key] = FlowStats(packets=10, bytes_sent=2000)
    state.flows[key].sni = "c2.evil.com"

    findings = SNIMismatchDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "sni_without_dns"
    assert findings[0].value == "c2.evil.com"
    assert findings[0].evidence["flow_count"] == 1


def test_sni_mismatch_ignores_sni_in_dns():
    """SNI есть и домен резолвился — нормально, не finding."""
    state = CaptureState()
    state.dns_queries["example.com"] = 1

    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.100", dst_ip="203.0.113.66",
        src_port=54000, dst_port=443,
    )
    state.flows[key] = FlowStats(packets=10, bytes_sent=2000)
    state.flows[key].sni = "example.com"

    findings = SNIMismatchDetector().run(state, Config())

    assert findings == []


def test_sni_mismatch_ignores_flow_without_sni():
    """Flow без SNI (не TLS) — не проверяется."""
    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.100", dst_ip="203.0.113.66",
        src_port=54000, dst_port=80,
    )
    state.flows[key] = FlowStats(packets=10, bytes_sent=2000)

    findings = SNIMismatchDetector().run(state, Config())

    assert findings == []


def test_sni_mismatch_ignores_allowlisted():
    """DoH-сервисы не считаются mismatch — их SNI по определению не в DNS."""
    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="192.168.1.100", dst_ip="8.8.8.8",
        src_port=54000, dst_port=443,
    )
    state.flows[key] = FlowStats(packets=5, bytes_sent=500)
    state.flows[key].sni = "dns.google"

    findings = SNIMismatchDetector().run(state, Config())

    assert findings == []


def test_sni_mismatch_aggregates_same_sni():
    """Несколько flows с одним SNI → один finding с flow_count=3."""
    state = CaptureState()
    for sport in (54000, 54001, 54002):
        key = FlowKey(
            proto="tcp",
            src_ip="192.168.1.100", dst_ip="203.0.113.66",
            src_port=sport, dst_port=443,
        )
        state.flows[key] = FlowStats(packets=10, bytes_sent=1000)
        state.flows[key].sni = "c2.evil.com"

    findings = SNIMismatchDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 3


def test_sni_mismatch_separate_sni():
    """Разные SNI → разные findings."""
    state = CaptureState()
    for sni, dst in [("c2-a.evil.com", "203.0.113.1"),
                     ("c2-b.evil.com", "203.0.113.2")]:
        key = FlowKey(
            proto="tcp",
            src_ip="192.168.1.100", dst_ip=dst,
            src_port=54000, dst_port=443,
        )
        state.flows[key] = FlowStats(packets=5, bytes_sent=500)
        state.flows[key].sni = sni

    findings = SNIMismatchDetector().run(state, Config())

    assert len(findings) == 2
    values = sorted(f.value for f in findings)
    assert values == ["c2-a.evil.com", "c2-b.evil.com"]

    # ---------- VulnerablePathDetector ----------


def test_vulnerable_path_wp_plugin():
    from pcap_triage.detectors.vulnerable_path import VulnerablePathDetector

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="10.50.3.8", dst_ip="10.100.18.5",
        src_port=49510, dst_port=80,
    )
    fs = FlowStats(packets=1, bytes_sent=25500)
    fs.http_uri = "/wp-content/plugins/post-content-shortcodes/styles/default-styles.css"
    fs.http_host = "nasledie.samregion.ru"
    fs.http_method = "GET"
    state.flows[key] = fs

    findings = VulnerablePathDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "vulnerable_path"
    assert findings[0].evidence["matched_paths"][0]["path"] == \
           "wp-content/plugins/post-content-shortcodes"


def test_vulnerable_path_script_download_ps1():
    from pcap_triage.detectors.vulnerable_path import VulnerablePathDetector

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="10.0.1.50", dst_ip="192.168.1.1",
        src_port=54000, dst_port=80,
    )
    fs = FlowStats(packets=1, bytes_sent=500)
    fs.http_uri = "/watch_movie.ps1"
    fs.http_host = "10.0.1.152"
    fs.http_method = "GET"
    state.flows[key] = fs

    findings = VulnerablePathDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type in ("vulnerable_path", "script_download")
    assert findings[0].value == "/watch_movie.ps1"


def test_vulnerable_path_script_download_sh():
    from pcap_triage.detectors.vulnerable_path import VulnerablePathDetector

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="10.0.1.50", dst_ip="10.0.1.152",
        src_port=55000, dst_port=80,
    )
    fs = FlowStats(packets=1, bytes_sent=500)
    fs.http_uri = "/ftp_update.sh"
    fs.http_host = "10.0.1.152"
    state.flows[key] = fs

    findings = VulnerablePathDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "script_download"
    assert findings[0].evidence["extension"] == ".sh"


def test_vulnerable_path_ignores_normal_uri():
    from pcap_triage.detectors.vulnerable_path import VulnerablePathDetector

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="10.0.1.50", dst_ip="8.8.8.8",
        src_port=54000, dst_port=80,
    )
    fs = FlowStats(packets=1, bytes_sent=500)
    fs.http_uri = "/api/v1/users"
    fs.http_host = "example.com"
    state.flows[key] = fs

    findings = VulnerablePathDetector().run(state, Config())

    assert findings == []


def test_vulnerable_path_ignores_no_uri():
    from pcap_triage.detectors.vulnerable_path import VulnerablePathDetector

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="10.0.1.50", dst_ip="8.8.8.8",
        src_port=54000, dst_port=443,
    )
    fs = FlowStats(packets=1, bytes_sent=500)
    state.flows[key] = fs

    findings = VulnerablePathDetector().run(state, Config())

    assert findings == []


def test_vulnerable_path_queries_in_uri():
    """Расширение с ?query — тоже должно ловиться."""
    from pcap_triage.detectors.vulnerable_path import VulnerablePathDetector

    state = CaptureState()
    key = FlowKey(
        proto="tcp",
        src_ip="10.0.1.50", dst_ip="8.8.8.8",
        src_port=54000, dst_port=80,
    )
    fs = FlowStats(packets=1, bytes_sent=500)
    fs.http_uri = "/script.ps1?param=1"
    fs.http_host = "example.com"
    state.flows[key] = fs

    findings = VulnerablePathDetector().run(state, Config())

    assert len(findings) == 1
    assert findings[0].type == "script_download"