from pathlib import Path
from fix_utils import patch

FIX_ID = "fix_23"
TITLE = "Refactor pipeline: extract _build_report to remove duplication"


def apply(root: Path) -> bool:
    rel = "paradox/pipeline.py"

    # 1. Вставляем общую функцию _build_report перед run_pipeline
    common_func = '''\
def _build_report(
    state: CaptureState,
    findings: list,
    config: Config,
    provenance: dict,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[..., None] | None = None,
) -> dict:
    """Общая часть сборки отчёта для run_pipeline и run_multi_pipeline."""
    if on_phase is not None:
        on_phase("contradictions", 0, 1)
    contradictions = run_contradictions(state, findings, config)
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
    absence_report = analyze_absence(state)

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
            })
            ioc_files = {
                k: str(v) for k, v in
                write_ioc_files(ioc_report, config.output_dir).items()
            }
        except Exception:
            ioc_files = {}

    ndp_report = {
        "total": getattr(state, "ndp_total", 0),
        "neighbors": [{"ip": k, "mac": v} for k, v in getattr(state, "ndp_neighbors", {}).items()],
        "routers": list(getattr(state, "ndp_routers", set())),
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
            "tcp_streams": len(state.tcp_streams),
            "tcp_streams_truncated": len(state.tcp_streams_truncated),
            "http_objects": len(state.http_objects),
            "carved_files": len(state.carved_files),
            **direction_summary,
        },
        "entities": {
            "internal": [e.to_dict() for e in entities.internal],
            "external": [e.to_dict() for e in entities.external],
        },
        "dns": dns_report,
        "ndp": ndp_report,
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


def run_pipeline('''

    changed = patch(
        root, rel,
        old="def run_pipeline(\n    pcap_path: Path,\n    config: Config,\n    should_stop: Callable[[], bool] | None = None,\n    on_progress: Callable[[int, int], None] | None = None,\n    on_phase: Callable[..., None] | None = None,\n) -> dict:\n",
        new=common_func + "    pcap_path: Path,\n    config: Config,\n    should_stop: Callable[[], bool] | None = None,\n    on_progress: Callable[[int, int], None] | None = None,\n    on_phase: Callable[..., None] | None = None,\n) -> dict:\n",
        count=1,
        required=True
    )

    # 2. Убираем дублирование из run_pipeline
    # Найдем кусок от "if on_phase is not None:\n        on_phase(\"contradictions\", 0, 1)" до "return {"
    old_run_pipeline_body = '''\
    # Contradictions — между detectors и build_entities.
    # После detectors: используют findings. До entities: влияют на роли (pivot).
    if on_phase is not None:
        on_phase("contradictions", 0, 1)
    contradictions = run_contradictions(state, findings, config)
    if on_phase is not None:
        on_phase("contradictions", 1, 1)
        on_phase("report", 0, 1)

    # v0.8.0: timeline / kill-chain reconstruction.
    # Собираем события из findings + contradictions, сортируем по ts,
    # группируем по фазам kill-chain (группировка — на стороне reporters).
    # Делается ДО reporters: они читают готовый список.
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
    absence_report = analyze_absence(state)

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
            })
            ioc_files = {
                k: str(v) for k, v in
                write_ioc_files(ioc_report, config.output_dir).items()
            }
        except Exception:
            ioc_files = {}

    ndp_report = {
        "total": getattr(state, "ndp_total", 0),
        "neighbors": [{"ip": k, "mac": v} for k, v in getattr(state, "ndp_neighbors", {}).items()],
        "routers": list(getattr(state, "ndp_routers", set())),
    }

    return {
        # 0.3.0: добавлен top-level ключ "contradictions".
        "schema_version": "0.3.0",
        "provenance": {
            "tool_version": __version__,
            "pcap_path": str(pcap_path),
            "pcap_sha256": sha256_file(pcap_path),
        },
        "summary": {
            "packets": state.packet_count,
            "unique_dns_queries": len(state.dns_queries),
            "nxdomain_count": sum(state.dns_nxdomain.values()),
            "flows": len(state.flows),
            "findings": len(findings),
            "contradictions": len(contradictions),
            "extractor_errors": dict(state.extractor_errors),
            "tcp_streams": len(state.tcp_streams),
            "tcp_streams_truncated": len(state.tcp_streams_truncated),
            "http_objects": len(state.http_objects),
            "carved_files": len(state.carved_files),
            **direction_summary,
        },
        "entities": {
            "internal": [e.to_dict() for e in entities.internal],
            "external": [e.to_dict() for e in entities.external],
        },
        "dns": dns_report,
        "ndp": ndp_report,
        "flows": flow_report,
        "http": http_report,
        "http_objects": http_objects_report,
        "carved_files": carved_report,
        "findings": [f.to_dict() for f in findings],
        "contradictions": [c.to_dict() for c in contradictions],
        # v1.2: attack graph
        "attack_graph": _attack_graph_dict,
        # v0.8.0: timeline / kill-chain reconstruction.
        # Плоский список TimelineEvent, отсортированный по ts.
        "timeline": [e.to_dict() for e in timeline_events],
        # v0.9.0: пути записанных IOC-файлов (пустой dict если отключено).
        "absence": absence_report,
        "ioc_files": ioc_files,
    }
'''
    new_run_pipeline_body = '''\
    provenance = {
        "tool_version": __version__,
        "pcap_path": str(pcap_path),
        "pcap_sha256": sha256_file(pcap_path),
    }
    return _build_report(state, findings, config, provenance, should_stop, on_phase)
'''

    changed |= patch(
        root, rel,
        old=old_run_pipeline_body,
        new=new_run_pipeline_body,
        count=1,
        required=True
    )

    # 3. Убираем дублирование из run_multi_pipeline
    old_multi_body = '''\
    # 4. Contradictions + timeline
    if on_phase is not None:
        on_phase("contradictions", 0, 1)
    contradictions = run_contradictions(state, findings, config)
    if on_phase is not None:
        on_phase("contradictions", 1, 1)
        on_phase("report", 0, 1)

    timeline_events = build_timeline(
        findings, contradictions, carved_files=state.carved_files,
    )

    # 5. Отчёты — переиспользуем существующие builders
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
    absence_report = analyze_absence(state)
    entities = build_entities(
        state, findings, config, contradictions=contradictions,
    )
    direction_summary = _summarize_direction(state, config)

    # 6. Attack graph
    try:
        from paradox.analyzers.attack_graph import build_attack_graph
        attack_graph = build_attack_graph(
            findings=findings, config=config,
            entities=entities, contradictions=contradictions,
        )
        attack_graph_dict = attack_graph.to_dict()
    except ImportError:
        attack_graph_dict = {"nodes": [], "edges": [], "paths": [],
                             "entry_points": [], "impact_targets": [],
                             "stats": {"nodes_total": 0, "edges_total": 0, "paths_total": 0}}

    # 7. IOC export
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
            })
            ioc_files = {
                k: str(v) for k, v in
                write_ioc_files(ioc_report, config.output_dir).items()
            }
        except Exception:
            ioc_files = {}

    ndp_report = {
        "total": getattr(state, "ndp_total", 0),
        "neighbors": [{"ip": k, "mac": v} for k, v in getattr(state, "ndp_neighbors", {}).items()],
        "routers": list(getattr(state, "ndp_routers", set())),
    }

    return {
        "schema_version": "0.3.0",
        "provenance": {
            "tool_version": __version__,
            "pcap_path": f"merged:{total} files",
            "pcap_sha256": "merged",
            "merged_files": [str(p) for p in pcap_paths],
        },
        "summary": {
            "packets": state.packet_count,
            "unique_dns_queries": len(state.dns_queries),
            "nxdomain_count": sum(state.dns_nxdomain.values()),
            "flows": len(state.flows),
            "findings": len(findings),
            "contradictions": len(contradictions),
            "extractor_errors": dict(state.extractor_errors),
            "tcp_streams": len(state.tcp_streams),
            "tcp_streams_truncated": len(state.tcp_streams_truncated),
            "http_objects": len(state.http_objects),
            "carved_files": len(state.carved_files),
            **direction_summary,
        },
        "entities": {
            "internal": [e.to_dict() for e in entities.internal],
            "external": [e.to_dict() for e in entities.external],
        },
        "dns": dns_report,
        "ndp": ndp_report,
        "flows": flow_report,
        "http": http_report,
        "http_objects": http_objects_report,
        "carved_files": carved_report,
        "findings": [f.to_dict() for f in findings],
        "contradictions": [c.to_dict() for c in contradictions],
        "attack_graph": attack_graph_dict,
        "timeline": [e.to_dict() for e in timeline_events],
        "absence": absence_report,
        "ioc_files": ioc_files,
    }
'''
    new_multi_body = '''\
    provenance = {
        "tool_version": __version__,
        "pcap_path": f"merged:{total} files",
        "pcap_sha256": "merged",
        "merged_files": [str(p) for p in pcap_paths],
    }
    return _build_report(state, findings, config, provenance, should_stop, on_phase)
'''

    changed |= patch(
        root, rel,
        old=old_multi_body,
        new=new_multi_body,
        count=1,
        required=True
    )

    return changed
