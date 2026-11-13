"""Доменные находки получают dst_ip — иначе они не попадают в граф атаки.

Регрессия с захвата 2026-10-16 (Coruna-like): dga_domain и
ip_check_service без dst_ip давали пустой attack_graph
(nodes_total=0), хотя внешние хосты в flows были.
"""
from __future__ import annotations

from paradox.models import CaptureState, Finding, FlowKey, FlowStats
from paradox.pipeline.detect import _resolve_domain_destinations


def _finding(ftype: str, value: str, src_ip: str = "10.0.0.5") -> Finding:
    return Finding(type=ftype, value=value, confidence=0.7, src_ip=src_ip)


def test_domain_finding_gets_single_dns_answer():
    state = CaptureState()
    state.dns_answers_by_name["evil.example"] = {"203.0.113.5"}
    finding = _finding("dga_domain", "evil.example")

    _resolve_domain_destinations(state, [finding])

    assert finding.dst_ip == "203.0.113.5"
    assert finding.evidence["resolved_ips"] == ["203.0.113.5"]


def test_domain_finding_prefers_contacted_ip_over_dns():
    """Хост реально ходил на один из адресов CDN — берём его, а не весь ответ."""
    state = CaptureState()
    state.dns_answers_by_name["cdn.example"] = {"203.0.113.5", "203.0.113.6"}
    key = FlowKey("tcp", "10.0.0.5", "203.0.113.6", 51000, 443)
    state.flows[key] = FlowStats(packets=10, bytes_sent=1000, sni="cdn.example")
    finding = _finding("typosquatting", "cdn.example")

    _resolve_domain_destinations(state, [finding])

    assert finding.dst_ip == "203.0.113.6"


def test_ambiguous_dns_leaves_dst_ip_empty():
    """Несколько A-записей и ни одного соединения — не угадываем."""
    state = CaptureState()
    state.dns_answers_by_name["cdn.example"] = {"203.0.113.5", "203.0.113.6"}
    finding = _finding("dga_domain", "cdn.example")

    _resolve_domain_destinations(state, [finding])

    assert finding.dst_ip is None
    assert "resolved_ips" not in finding.evidence


def test_cname_answer_is_not_treated_as_ip():
    state = CaptureState()
    state.dns_answers_by_name["updates.example"] = {
        "updates.example.edgekey.net",  # CNAME, не A
    }
    finding = _finding("dga_domain", "updates.example")

    _resolve_domain_destinations(state, [finding])

    assert finding.dst_ip is None


def test_existing_dst_ip_is_kept():
    state = CaptureState()
    state.dns_answers_by_name["evil.example"] = {"203.0.113.5"}
    finding = _finding("dga_domain", "evil.example")
    finding.dst_ip = "198.51.100.7"

    _resolve_domain_destinations(state, [finding])

    assert finding.dst_ip == "198.51.100.7"


def test_non_domain_finding_is_ignored():
    """script_download с URL не трогаем — это не голый домен."""
    state = CaptureState()
    state.dns_answers_by_name["evil.example"] = {"203.0.113.5"}
    finding = _finding("script_download", "http://evil.example/x.sh")

    _resolve_domain_destinations(state, [finding])

    assert finding.dst_ip is None
