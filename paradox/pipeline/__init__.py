"""Сборка прогона: тонкий фасад над стадиями pipeline.

Реализация разложена по этапам: ``extract`` (пакетный цикл),
``detect`` (детекторы), ``summarize`` (срезы отчёта) и ``report``
(сборка JSON). Публичные точки входа и списки этапов остаются здесь:
тесты и GUI патчат ``paradox.pipeline.<name>``.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from paradox import __version__
from paradox.config import Config
from paradox.models import CaptureState
from paradox.pipeline.detect import DETECTORS, _detect
from paradox.pipeline.errors import PipelineCancelled
from paradox.pipeline.extract import EXTRACTORS, _extract, sha256_file
from paradox.pipeline.report import _build_report
from paradox.pipeline.summarize import (
    _L7_BY_PORT,
    _classify_l7,
    _summarize_direction,
    _summarize_mitre,
    _summarize_protocols,
)

__all__ = [
    "DETECTORS",
    "EXTRACTORS",
    "PipelineCancelled",
    "_L7_BY_PORT",
    "_build_report",
    "_classify_l7",
    "_detect",
    "_extract",
    "_summarize_direction",
    "_summarize_mitre",
    "_summarize_protocols",
    "run_multi_pipeline",
    "run_pipeline",
    "sha256_file",
]


def _run_behavioral(
    state: CaptureState,
    config: Config,
    findings: list,
) -> None:
    """Поведенческий (ML) слой между детекторами и противоречиями.

    Два эффекта:
      1. аннотирует rule-находки поведенческим выбросом (corroborate),
      2. создаёт host_behavior_anomaly для хостов с аномальным профилем.

    По умолчанию выключен (behavioral_enabled=False) и не импортирует
    ML-код вовсе. Ошибка слоя не валит прогон — считается в
    summary.extractor_errors["behavioral"].
    """
    if not config.behavioral_enabled:
        return
    try:
        from paradox.analyzers.behavioral_analyzer import (
            BehavioralAnalyzer,
            corroborate,
        )

        corroborate(findings, state, config)
        findings.extend(BehavioralAnalyzer().score_hosts(state, config))
    except Exception:
        prev = state.extractor_errors["behavioral"]
        state.extractor_errors["behavioral"] = prev + 1


def run_pipeline(
    pcap_path: str | Path,
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
    detectors: list | None = None,
    rules: list | None = None,
) -> dict:
    pcap_path = Path(pcap_path)
    state = CaptureState()

    pcap_sha256 = _extract(
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
    _run_behavioral(state, config, findings)

    provenance = {
        "tool_version": __version__,
        "pcap_path": str(pcap_path),
        "pcap_sha256": pcap_sha256 or sha256_file(pcap_path),
    }
    return _build_report(
        state, findings, config, provenance,
        should_stop, on_phase, rules=rules,
    )


def run_multi_pipeline(
    pcap_paths: list[str | Path],
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_phase: Callable[..., None] | None = None,
    detectors: list | None = None,
    rules: list | None = None,
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

    pcap_paths = [Path(p) for p in pcap_paths]

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
    findings = _detect(
        state, config,
        should_stop=should_stop, on_phase=on_phase,
        detectors=detectors,
    )
    _run_behavioral(state, config, findings)

    provenance = {
        "tool_version": __version__,
        "pcap_path": f"merged:{total} files",
        "pcap_sha256": "merged",
        "merged_files": [str(p) for p in pcap_paths],
    }
    return _build_report(
        state, findings, config, provenance,
        should_stop, on_phase, rules=rules,
    )
