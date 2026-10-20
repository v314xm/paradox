"""Углублённые тесты markdown_reporter: TL;DR, entities, timeline."""
from paradox.reporters.markdown_reporter import render_markdown


def _base(**extra) -> dict:
    base = {
        "provenance": {
            "tool_version": "1.0.0",
            "pcap_path": "test.pcap",
            "pcap_sha256": "a" * 64,
        },
        "summary": {
            "packets": 100, "flows": 10,
            "unique_dns_queries": 5, "nxdomain_count": 1,
            "findings": 0, "contradictions": 0,
            "extractor_errors": {},
        },
        "findings": [],
        "contradictions": [],
        "entities": {"internal": [], "external": []},
        "flows": {"top_by_bytes": []},
        "http": {},
        "carved_files": {"files": []},
        "absence": {},
        "ndp": {},
    }
    base.update(extra)
    return base


def test_markdown_tldr_pivot():
    """contradictions с victim_makes_attack → в отчёте PIVOT."""
    report = _base(contradictions=[{
        "rule": "victim_makes_attack",
        "subject": "192.168.1.12",
        "severity": "critical",
        "confidence": 0.9,
        "facts": [],
        "likely_causes": ["pivot"],
        "resolution_hint": "check",
    }])
    report["summary"]["contradictions"] = 1
    md = render_markdown(report)
    # В TL;DR должен быть pivot marker
    assert "PIVOT" in md or "pivot" in md.lower()
    assert "192.168.1.12" in md


def test_markdown_entities_with_hostname_and_mac():
    """entities с MAC/hostname/username → всё рисуется."""
    report = _base(entities={
        "internal": [{
            "ip": "10.0.0.5",
            "is_internal": True,
            "roles": ["victim_candidate"],
            "flows_out": 10, "flows_in": 20,
            "bytes_out": 1000, "bytes_in": 5000,
            "unique_dsts": [], "unique_srcs": [],
            "sni_domains": ["example.com"],
            "dns_names": ["example.com"],
            "findings_indices": [],
            "service_flows_in": 0,
            "service_unique_srcs": [],
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "desktop-01",
            "username": "alice",
            "realm": "EXAMPLE.COM",
            "asn": None, "country": None,
            "first_seen": 100.0, "last_seen": 200.0,
        }],
        "external": [],
    })
    md = render_markdown(report)
    assert "10.0.0.5" in md
    assert "desktop-01" in md or "hostname" in md.lower()
    assert "aa:bb:cc:dd:ee:ff" in md
    assert "alice" in md
    assert "EXAMPLE.COM" in md


def test_markdown_timeline_flat():
    """report["timeline"] есть → секция Timeline с фазами."""
    report = _base(
        findings=[{
            "type": "dga_domain",
            "value": "test.example",
            "confidence": 0.8,
            "severity": "medium",
            "mitre_techniques": [],
            "evidence": {},
        }],
        timeline=[{
            "ts": 100.0,
            "kind": "finding",
            "type": "dga_domain",
            "subject": "10.0.0.5",
            "severity": "medium",
            "confidence": 0.8,
            "phase": "c2",
            "chain_order": 60,
            "description": "dga from 10.0.0.5",
            "mitre_id": "T1568.002",
            "ref_id": 0,
        }],
    )
    report["summary"]["findings"] = 1
    md = render_markdown(report)
    assert "## Timeline" in md
    assert "c2" in md  # фаза
    assert "10.0.0.5" in md


def test_markdown_extractor_errors_shown():
    """extractor_errors != {} → строка с ошибками в summary."""
    report = _base()
    report["summary"]["extractor_errors"] = {"dns": 3, "tls": 1}
    md = render_markdown(report)
    assert "extractor_errors" in md or "Ошибки" in md


def test_markdown_ndp_section():
    """NDP-трафик → секция IPv6."""
    report = _base(ndp={
        "total": 5,
        "neighbors": [{"ip": "fe80::1", "mac": "aa:bb:cc:dd:ee:ff"}],
        "routers": ["fe80::2"],
    })
    md = render_markdown(report)
    assert "IPv6" in md or "NDP" in md
    assert "fe80::1" in md
