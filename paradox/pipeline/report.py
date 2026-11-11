"""Сборка отчёта из CaptureState и findings."""
from __future__ import annotations

from collections.abc import Callable

from paradox.aggregators.entities import build_entities
from paradox.analyzers.absence import analyze_absence
from paradox.config import Config
from paradox.contradictions import run_all as run_contradictions
from paradox.models import CaptureState
from paradox.pipeline.summarize import (
    _summarize_direction,
    _summarize_mitre,
    _summarize_protocols,
)
from paradox.reporters.flow_report import (
    build_dns_report,
    build_flow_report,
    build_http_object_report,
    build_http_report,
)
from paradox.timeline import build_timeline


def _build_report(
    state: CaptureState,
    findings: list,
    config: Config,
    provenance: dict,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[..., None] | None = None,
    rules: list | None = None,
) -> dict:
    """Общая часть сборки отчёта для run_pipeline и run_multi_pipeline.

    rules — опциональный список правил contradictions (default —
    глобальный RULES). Позволяет GUI отключать правила без monkey-patch.
    """
    if on_phase is not None:
        on_phase("contradictions", 0, 1)
    contradictions = run_contradictions(state, findings, config, rules=rules)
    if on_phase is not None:
        on_phase("contradictions", 1, 1)
        on_phase("report", 0, 1)

    timeline_events = build_timeline(
        findings, contradictions, carved_files=state.carved_files,
    )

    flow_report = build_flow_report(state, config, top_n=config.flow_report_top_n)
    dns_report = build_dns_report(state, top_n=config.flow_report_top_n)
    http_report = build_http_report(state, top_n=config.flow_report_top_n)
    http_objects_report = build_http_object_report(
        state, top_n=config.flow_report_top_n,
    )
    carved_report = {
        "total": len(state.carved_files),
        "files": [c.to_dict() for c in state.carved_files],
        "mitre": _summarize_mitre(findings),
    }
    absence_report = analyze_absence(state, top_n=config.absence_top_n)

    entities = build_entities(
        state, findings, config, contradictions=contradictions,
    )
    # v1.2: attack graph
    try:
        from paradox.analyzers.attack_graph import build_attack_graph
        _attack_graph = build_attack_graph(
            findings=findings, config=config,
            entities=entities, contradictions=contradictions,
        )
        _attack_graph_dict = _attack_graph.to_dict()
    except Exception:
        import logging
        logging.getLogger(__name__).exception(
            "build_attack_graph failed; falling back to empty graph"
        )
        _attack_graph_dict = {
            "nodes": [], "edges": [], "paths": [],
            "entry_points": [], "impact_targets": [],
            "stats": {"nodes_total": 0, "edges_total": 0, "paths_total": 0},
        }
    direction_summary = _summarize_direction(state, config)
    protocol_summary = _summarize_protocols(state, config)

    # v0.9.0: экспорт IOC для EDR/SIEM.
    ioc_files: dict = {}
    if getattr(config, "ioc_export_enabled", True):
        try:
            from paradox.reporters.ioc_reporter import (
                build_ioc_report,
                write_ioc_files,
            )
            ioc_report = build_ioc_report({
                "findings": [f.to_dict() for f in findings],
                "carved_files": carved_report,
                "absence": absence_report,
            }, config)
            ioc_files = {
                k: str(v) for k, v in
                write_ioc_files(ioc_report, config.output_dir).items()
            }
        except Exception:
            ioc_files = {}

    ndp_report = {
        "total": state.ndp_total,
        "neighbors": [{"ip": k, "mac": v} for k, v in state.ndp_neighbors.items()],
        "routers": list(state.ndp_routers),
    }

    cert_limit = config.flow_report_top_n
    certificates_report = {
        "total": len(state.tls_certs),
        "parse_errors": state.tls_cert_parse_errors,
        "truncated": len(state.tls_certs) > cert_limit,
        "items": [
            {
                "src_ip": key.src_ip,
                "dst_ip": key.dst_ip,
                "dst_port": key.dst_port,
                "subject_cn": cert.subject_cn,
                "issuer_cn": cert.issuer_cn,
                "self_signed": cert.is_self_signed,
                "not_before": cert.not_before,
                "not_after": cert.not_after,
                "san_dns": list(cert.san_dns),
                "san_ips": list(cert.san_ips),
            }
            for key, cert in state.tls_certs[:cert_limit]
        ],
    }

    return {
        "schema_version": "0.3.0",
        "provenance": provenance,
        "summary": {
            "packets": state.packet_count,
            "unique_dns_queries": len(state.dns_queries),
            "nxdomain_count": sum(state.dns_nxdomain.values()),
            "flows": len(state.flows),
            "findings": len(findings),
            "contradictions": len(contradictions),
            "extractor_errors": dict(state.extractor_errors),
            "tcp_streams": state.tcp_streams_total or len(state.tcp_streams),
            "tcp_streams_truncated": len(state.tcp_streams_truncated),
            "http_objects": len(state.http_objects),
            "carved_files": len(state.carved_files),
            "certificates": len(state.tls_certs),
            "tls_cert_parse_errors": state.tls_cert_parse_errors,
            **direction_summary,
            "protocols": protocol_summary,
        },
        "entities": {
            "internal": [e.to_dict() for e in entities.internal],
            "external": [e.to_dict() for e in entities.external],
        },
        "dns": dns_report,
        "ndp": ndp_report,
        "certificates": certificates_report,
        "flows": flow_report,
        "http": http_report,
        "http_objects": http_objects_report,
        "carved_files": carved_report,
        "findings": [f.to_dict() for f in findings],
        "contradictions": [c.to_dict() for c in contradictions],
        "attack_graph": _attack_graph_dict,
        "timeline": [e.to_dict() for e in timeline_events],
        "absence": absence_report,
        "ioc_files": ioc_files,
    }
