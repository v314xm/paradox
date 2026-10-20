"""Тесты Counterfactual (what-if) анализа."""
from paradox.analyzers.counterfactual import evaluate_what_if


def test_what_if_empty():
    assert evaluate_what_if({})["original_count"] == 0


def test_what_if_exclude_ip():
    report = {
        "findings": [
            {"type": "port_scan", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.10", "value": "scan"},
            {"type": "dga", "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "value": "bad.com"},
        ]
    }

    res = evaluate_what_if(report, exclude_ips=["10.0.0.5"])

    assert res["original_count"] == 2
    assert res["removed_count"] == 1
    assert res["remaining_count"] == 1
    assert res["removed_findings"][0]["type"] == "port_scan"
    assert res["remaining_findings"][0]["type"] == "dga"


def test_what_if_exclude_domain():
    report = {
        "findings": [
            {"type": "dga", "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "value": "bad.com"},
            {"type": "dga", "src_ip": "10.0.0.11", "dst_ip": "8.8.8.8", "value": "good.com", "evidence": {"domain": "good.com"}},
        ]
    }

    res = evaluate_what_if(report, exclude_domains=["bad.com"])

    assert res["original_count"] == 2
    assert res["removed_count"] == 1
    assert res["remaining_count"] == 1
    assert res["remaining_findings"][0]["value"] == "good.com"


def test_what_if_combined():
    report = {
        "findings": [
            {"type": "port_scan", "src_ip": "10.0.0.5", "value": "scan"},
            {"type": "dga", "value": "bad.com"},
            {"type": "beaconing", "src_ip": "10.0.0.10", "value": "good.com"},
        ]
    }

    res = evaluate_what_if(report, exclude_ips=["10.0.0.5"], exclude_domains=["bad.com"])

    assert res["original_count"] == 3
    assert res["removed_count"] == 2
    assert res["remaining_count"] == 1
    assert res["remaining_findings"][0]["type"] == "beaconing"
