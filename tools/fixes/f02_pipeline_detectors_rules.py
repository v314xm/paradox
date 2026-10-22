"""f02: pipeline.py — параметры detectors=/rules= и try/except.

Снимает monkey-patch глобальных DETECTORS/RULES. Заодно: один
сломанный детектор не валит весь прогон (try/except + счётчик
в state.extractor_errors под ключом "detector:<name>").
"""
from pathlib import Path

from tools._patcher import assert_applied, patch

NAME = "f02: pipeline.py — detectors/rules params + try/except"
FILES = ["paradox/pipeline.py"]

_OLD_DETECT = '''def _detect(
    state: CaptureState,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[[str, int, int], None] | None = None,
):
    findings = []
    total = len(DETECTORS)
    for i, det in enumerate(DETECTORS):
        if should_stop is not None and should_stop():
            raise PipelineCancelled()
        if on_phase is not None:
            on_phase("detect", i, total, det.name)
        findings.extend(det.run(state, config))
        if on_phase is not None:
            on_phase("detect", i + 1, total, det.name)'''

_NEW_DETECT = '''def _detect(
    state: CaptureState,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_phase: Callable[[str, int, int], None] | None = None,
    detectors: list | None = None,
):
    # v1.4: детекторы — параметром, без monkey-patch глобального
    # DETECTORS (thread-safe для параллельных воркеров).
    # Каждый детектор обёрнут в try/except: один упавший не валит
    # остальные. Ошибки считаются в state.extractor_errors с префиксом
    # "detector:<name>" — их видно в summary отчёта.
    active = list(detectors) if detectors is not None else DETECTORS
    findings = []
    total = len(active)
    for i, det in enumerate(active):
        if should_stop is not None and should_stop():
            raise PipelineCancelled()
        if on_phase is not None:
            on_phase("detect", i, total, det.name)
        try:
            findings.extend(det.run(state, config))
        except Exception:
            key = f"detector:{det.name}"
            prev = state.extractor_errors[key]
            state.extractor_errors[key] = prev + 1
            if getattr(config, "debug_log_extractor_errors", False) and prev == 0:
                import logging
                logging.exception(
                    "detector %s failed (first occurrence)", det.name,
                )
        if on_phase is not None:
            on_phase("detect", i + 1, total, det.name)'''

_OLD_REPORT_SIG = '''def _build_report(
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
    contradictions = run_contradictions(state, findings, config)'''

_NEW_REPORT_SIG = '''def _build_report(
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
    contradictions = run_contradictions(state, findings, config, rules=rules)'''

_OLD_RUN_PIPELINE = '''def run_pipeline(    pcap_path: Path,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
) -> dict:
    state = CaptureState()

    _extract(
        pcap_path, state, config,
        should_stop=should_stop,
        on_progress=on_progress,
    )
    findings = _detect(
        state, config,
        should_stop=should_stop,
        on_phase=on_phase,
    )

    provenance = {
        "tool_version": __version__,
        "pcap_path": str(pcap_path),
        "pcap_sha256": sha256_file(pcap_path),
    }
    return _build_report(state, findings, config, provenance, should_stop, on_phase)'''

_NEW_RUN_PIPELINE = '''def run_pipeline(    pcap_path: Path,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
    detectors: list | None = None,
    rules: list | None = None,
) -> dict:
    state = CaptureState()

    _extract(
        pcap_path, state, config,
        should_stop=should_stop,
        on_progress=on_progress,
    )
    findings = _detect(
        state, config,
        should_stop=should_stop,
        on_phase=on_phase,
        detectors=detectors,
    )

    provenance = {
        "tool_version": __version__,
        "pcap_path": str(pcap_path),
        "pcap_sha256": sha256_file(pcap_path),
    }
    return _build_report(
        state, findings, config, provenance,
        should_stop, on_phase, rules=rules,
    )'''

_OLD_MULTI = '''    findings = _detect(state, config, should_stop=should_stop, on_phase=on_phase)

    provenance = {
        "tool_version": __version__,
        "pcap_path": f"merged:{total} files",
        "pcap_sha256": "merged",
        "merged_files": [str(p) for p in pcap_paths],
    }
    return _build_report(state, findings, config, provenance, should_stop, on_phase)'''

_NEW_MULTI = '''    findings = _detect(
        state, config,
        should_stop=should_stop, on_phase=on_phase,
        detectors=detectors,
    )

    provenance = {
        "tool_version": __version__,
        "pcap_path": f"merged:{total} files",
        "pcap_sha256": "merged",
        "merged_files": [str(p) for p in pcap_paths],
    }
    return _build_report(
        state, findings, config, provenance,
        should_stop, on_phase, rules=rules,
    )'''

_OLD_MULTI_SIG = '''def run_multi_pipeline(
    pcap_paths: list[Path],
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
) -> dict:'''

_NEW_MULTI_SIG = '''def run_multi_pipeline(
    pcap_paths: list[Path],
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
    detectors: list | None = None,
    rules: list | None = None,
) -> dict:'''


def apply(root: Path) -> bool:
    changed = False
    changed |= patch(root, FILES[0], _OLD_DETECT, _NEW_DETECT)
    changed |= patch(root, FILES[0], _OLD_REPORT_SIG, _NEW_REPORT_SIG)
    changed |= patch(root, FILES[0], _OLD_RUN_PIPELINE, _NEW_RUN_PIPELINE)
    changed |= patch(root, FILES[0], _OLD_MULTI_SIG, _NEW_MULTI_SIG)
    changed |= patch(root, FILES[0], _OLD_MULTI, _NEW_MULTI)
    return changed


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], "def _detect(\n    state: CaptureState,\n    config: Config,\n    should_stop: Callable[[], bool] | None = None,\n    on_phase: Callable[[str, int, int], None] | None = None,\n    detectors: list | None = None,\n)")
    assert_applied(root, FILES[0], "active = list(detectors) if detectors is not None else DETECTORS")
    assert_applied(root, FILES[0], "contradictions = run_contradictions(state, findings, config, rules=rules)")
    assert_applied(root, FILES[0], "        detectors=detectors,\n    )\n\n    provenance")
    assert_applied(root, FILES[0], "        detectors=detectors,\n    )\n\n    provenance = {")
