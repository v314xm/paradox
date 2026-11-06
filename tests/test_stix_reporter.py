"""
Тесты STIX 2.1 репортера (ядро, используется CLI и GUI).
"""
import json
import uuid

from paradox.reporters.stix_reporter import (
    build_stix_bundle,
    extract_iocs,
    indicator_id,
    render_stix_json,
    ts_to_iso,
    write_stix,
)


def _finding(**overrides):
    base = {
        "type": "typosquatting",
        "value": "dng-microsoftds.com",
        "src_ip": "192.168.1.10",
        "dst_ip": "104.21.16.1",
        "first_seen": 1700000000,
        "last_seen": 1700000100,
        "evidence": {},
    }
    base.update(overrides)
    return base


def test_indicator_id_is_deterministic():
    first = indicator_id("ipv4", "1.2.3.4")
    second = indicator_id("ipv4", "1.2.3.4")
    assert first == second
    assert first.startswith("indicator--")
    assert uuid.UUID(first.split("--", 1)[1])


def test_indicator_id_depends_on_type():
    assert indicator_id("ipv4", "1.2.3.4") != indicator_id("domain", "1.2.3.4")


def test_ts_to_iso_none_and_value():
    assert ts_to_iso(None) is None
    iso = ts_to_iso(1700000000)
    assert iso is not None
    assert iso.startswith("2023-11-")
    assert iso.endswith("+00:00")


def test_ts_to_iso_bad_value():
    assert ts_to_iso("not-a-number") is None


def test_private_ips_not_exported():
    indicators = extract_iocs([_finding()])
    values = {i["pattern"] for i in indicators}
    assert "[ipv4-addr:value = '104.21.16.1']" in values
    assert not any("192.168.1.10" in v for v in values)


def test_domain_from_value_and_evidence():
    findings = [
        _finding(value="x", evidence={"hosts": ["evil-c2.live"]}),
        _finding(value="other", evidence={"host": "windows-msgas.com"}),
    ]
    domains = {
        i["pattern"] for i in extract_iocs(findings)
        if i["name"] == "Domain"
    }
    assert "[domain-name:value = 'evil-c2.live']" in domains
    assert "[domain-name:value = 'windows-msgas.com']" in domains


def test_evidence_ip_is_not_treated_as_domain():
    indicators = extract_iocs([
        _finding(value="x", evidence={"hosts": ["104.21.16.1"]}),
    ])
    names = [i["name"] for i in indicators]
    assert "Domain" not in names


def test_dedup_same_value():
    findings = [
        _finding(dst_ip="104.21.16.1"),
        _finding(dst_ip="104.21.16.1", value="same"),
    ]
    ip_inds = [
        i for i in extract_iocs(findings)
        if i["pattern"].startswith("[ipv4-addr")
    ]
    assert len(ip_inds) == 1


def test_bundle_structure():
    bundle = build_stix_bundle({"findings": [_finding()]})
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)
    for ind in bundle["objects"]:
        assert ind["type"] == "indicator"
        assert ind["spec_version"] == "2.1"
        assert ind["pattern_type"] == "stix"
        assert ind["id"].startswith("indicator--")


def test_bundle_is_deterministic():
    report = {"findings": [_finding()]}
    assert build_stix_bundle(report)["id"] == build_stix_bundle(report)["id"]


def test_bundle_id_changes_with_content():
    one = build_stix_bundle({"findings": [_finding()]})
    two = build_stix_bundle({"findings": [_finding(dst_ip="8.8.8.8")]})
    assert one["id"] != two["id"]


def test_empty_report():
    bundle = build_stix_bundle({})
    assert bundle["type"] == "bundle"
    assert bundle["objects"] == []


def test_render_is_valid_json_and_keeps_cyrillic():
    rendered = render_stix_json({"findings": [_finding()]})
    parsed = json.loads(rendered)
    assert parsed["type"] == "bundle"
    assert "Найден в детекторе" in rendered


def test_write_stix(tmp_path):
    path = tmp_path / "out.stix.json"
    written = write_stix({"findings": [_finding()]}, path)
    assert written == path
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["objects"]
