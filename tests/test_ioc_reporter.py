"""Тесты IOC reporter."""
from pathlib import Path

from paradox.reporters.ioc_reporter import (
    build_ioc_report,
    render_iocs_csv,
    render_iocs_json,
    render_iocs_txt,
    render_queries,
    render_suricata_rules,
    write_ioc_files,
)


def _report_with_findings(*findings):
    return {"findings": list(findings), "carved_files": {"files": []}}


# ---------- build_ioc_report ----------

def test_empty_report():
    ioc = build_ioc_report({"findings": [], "carved_files": {"files": []}})
    assert ioc["domains"] == []
    assert ioc["ips"] == []
    assert ioc["sha256"] == []


def test_domain_from_dga():
    ioc = build_ioc_report(_report_with_findings({
        "type": "dga_domain", "value": "evil123.com",
        "severity": "medium",
    }))
    assert len(ioc["domains"]) == 1
    assert ioc["domains"][0]["value"] == "evil123.com"
    assert ioc["domains"][0]["source"] == "dga_domain"


def test_ip_from_suspicious_port():
    ioc = build_ioc_report(_report_with_findings({
        "type": "suspicious_port", "value": "203.0.113.66:4444",
        "dst_ip": "203.0.113.66", "severity": "medium",
    }))
    assert len(ioc["ips"]) == 1
    assert ioc["ips"][0]["value"] == "203.0.113.66"


def test_ip_from_nxdomain_burst():
    ioc = build_ioc_report(_report_with_findings({
        "type": "nxdomain_burst", "value": "10.0.0.5",
        "dst_ip": None, "severity": "low",
    }))
    # value — src_ip, а не dst. Не должно попасть в IP-list.
    assert ioc["ips"] == []


def test_sha256_from_carved():
    report = {
        "findings": [],
        "carved_files": {"files": [
            {"sha256": "a" * 64, "uri": "/evil.sh"},
            {"sha256": "b" * 64, "uri": "/payload.exe"},
        ]},
    }
    ioc = build_ioc_report(report)
    assert len(ioc["sha256"]) == 2
    assert {s["value"] for s in ioc["sha256"]} == {"a" * 64, "b" * 64}


def test_dedup_by_value():
    """Два finding'а с одним доменом — одна запись."""
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "evil.com", "severity": "low"},
        {"type": "cloud_tunnel", "value": "evil.com", "severity": "high"},
    ))
    assert len(ioc["domains"]) == 1
    # Максимальная severity.
    assert ioc["domains"][0]["severity"] == "high"


# ---------- render ----------

def test_txt_format():
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "evil.com", "severity": "high"},
    ))
    txt = render_iocs_txt(ioc)
    assert "# Domains" in txt
    assert "evil.com" in txt


def test_csv_format():
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "evil.com", "severity": "high"},
    ))
    csv = render_iocs_csv(ioc)
    assert "type,value,severity,source" in csv
    assert "evil.com" in csv


def test_json_format():
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "evil.com", "severity": "high"},
    ))
    js = render_iocs_json(ioc)
    assert '"evil.com"' in js
    import json as _json
    parsed = _json.loads(js)
    assert parsed["domains"][0]["value"] == "evil.com"


def test_suricata_high_only():
    """В suricata.rules только high/critical."""
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "high.com", "severity": "high"},
        {"type": "dga_domain", "value": "low.com", "severity": "low"},
    ))
    rules = render_suricata_rules(ioc)
    assert "high.com" in rules
    assert "low.com" not in rules


def test_suricata_sid_unique():
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "a.com", "severity": "high"},
        {"type": "dga_domain", "value": "b.com", "severity": "high"},
    ))
    rules = render_suricata_rules(ioc)
    # SID 9000001 и 9000002.
    assert "sid:9000001;" in rules
    assert "sid:9000002;" in rules


def test_queries_kql():
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "evil.com", "severity": "high"},
    ))
    q = render_queries(ioc)
    assert "DeviceNetworkEvents" in q
    assert '"evil.com"' in q
    assert "index=*" in q  # Splunk


# ---------- write_ioc_files ----------

def test_write_files(tmp_path):
    ioc = build_ioc_report(_report_with_findings(
        {"type": "dga_domain", "value": "evil.com", "severity": "high"},
        {"type": "suspicious_port", "value": "203.0.113.1:4444",
         "dst_ip": "203.0.113.1", "severity": "medium"},
    ))
    written = write_ioc_files(ioc, tmp_path)
    assert "txt" in written
    assert "csv" in written
    assert "json" in written
    assert "suricata" in written
    assert "queries" in written
    assert (tmp_path / "iocs.txt").exists()
    assert (tmp_path / "iocs.csv").exists()
    assert (tmp_path / "iocs.json").exists()
    assert (tmp_path / "suricata.rules").exists()
    assert (tmp_path / "queries.txt").exists()


def test_write_files_empty(tmp_path):
    """Пустой IOC — файлы не пишем."""
    ioc = build_ioc_report({"findings": [], "carved_files": {"files": []}})
    written = write_ioc_files(ioc, tmp_path)
    assert written == {}
    # Директория создана, но файлов нет.
    assert not (tmp_path / "iocs.txt").exists()


def test_config_flag_default():
    from paradox.config import Config
    cfg = Config()
    assert cfg.ioc_export_enabled is True
