"""Безопасная интеграция multi-pcap: дописываем run_multi_pipeline в конец pipeline.py."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE = REPO_ROOT / "paradox" / "pipeline.py"


NEW_FUNC = '''

def run_multi_pipeline(
    pcap_paths: list[Path],
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
) -> dict:
    """Multi-pcap: прогон нескольких файлов со слиянием в один отчёт.

    Не трогает run_pipeline. Внутри:
      1. _extract для каждого файла (накапливаем CaptureState)
      2. merge_capture_states(...) — склейка
      3. _detect на объединённом state (все детекторы видят длинный горизонт)
      4. run_contradictions, build_timeline, build_*_report — как в run_pipeline
    """
    from paradox.multi_pcap import merge_capture_states

    if not pcap_paths:
        raise ValueError("pcap_paths is empty")

    # 1. Извлечение
    states = []
    total = len(pcap_paths)
    for i, p in enumerate(pcap_paths, start=1):
        st = CaptureState()
        _extract(p, st, config, should_stop=should_stop, on_progress=on_progress)
        states.append(st)
        if on_progress:
            on_progress(i, total)

    if should_stop is not None and should_stop():
        raise PipelineCancelled()

    # 2. Слияние
    state = merge_capture_states(states)

    # 3. Детекторы
    findings = _detect(state, config, should_stop=should_stop, on_phase=on_phase)

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
                build_ioc_report, write_ioc_files,
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


def main():
    print("=" * 60)
    print(" add run_multi_pipeline (append-only)")
    print("=" * 60)

    if not PIPELINE.exists():
        print(f"[ERROR] {PIPELINE} not found", file=sys.stderr)
        return 1

    src = PIPELINE.read_text(encoding="utf-8")

    if "def run_multi_pipeline(" in src:
        print("[SKIP] run_multi_pipeline already exists")
        return 0

    # Проверка: все нужные импорты есть в pipeline.py
    required_imports = [
        "from paradox.models import CaptureState",
        "from paradox.aggregators.entities import build_entities",
        "from paradox.analyzers.absence import analyze_absence",
        "from paradox.contradictions import run_all as run_contradictions",
        "from paradox.timeline import build_timeline",
        "from paradox.reporters.flow_report import",
    ]
    missing = [imp for imp in required_imports if imp not in src]
    if missing:
        print("[ERROR] в pipeline.py не хватает импортов:", file=sys.stderr)
        for imp in missing:
            print(f"  {imp}", file=sys.stderr)
        return 2

    # Дописываем в конец
    new_src = src.rstrip() + "\n" + NEW_FUNC + "\n"
    PIPELINE.write_text(new_src, encoding="utf-8")
    print("[OK] run_multi_pipeline добавлен в конец pipeline.py")
    print(f"     (+{len(NEW_FUNC.splitlines())} строк)")

    # Проверка импорта
    print("\nVerifying import...")
    import importlib
    try:
        import paradox.pipeline
        importlib.reload(paradox.pipeline)
        if hasattr(paradox.pipeline, "run_multi_pipeline"):
            print("[OK] run_multi_pipeline доступен")
        else:
            print("[ERROR] функция не появилась", file=sys.stderr)
            return 3
    except Exception as e:
        print(f"[ERROR] import failed: {type(e).__name__}: {e}", file=sys.stderr)
        print("\nОткати: git checkout paradox/pipeline.py", file=sys.stderr)
        return 1

    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
