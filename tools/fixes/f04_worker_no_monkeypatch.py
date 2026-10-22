"""f04: analysis_worker — без monkey-patch DETECTORS/RULES.

Передаём active_detectors/active_rules как параметры в
run_pipeline/run_multi_pipeline. Глобальное состояние не мутируется.
"""
from pathlib import Path

from tools._patcher import assert_applied, assert_not_present, patch

NAME = "f04: analysis_worker.py — без monkey-patch"
FILES = ["paradox_gui/workers/analysis_worker.py"]

_OLD_IMPORTS = '''    def run(self) -> None:
        try:
            import paradox.pipeline as core
            from paradox.contradictions import registry as contra_registry
            from paradox.pipeline import (
                PipelineCancelled,
                run_multi_pipeline,
                run_pipeline,
            )
        except ImportError as e:
            self.error.emit(f"Не удалось импортировать ядро: {e}")
            return'''

_NEW_IMPORTS = '''    def run(self) -> None:
        try:
            from paradox.contradictions.registry import RULES
            from paradox.pipeline import (
                DETECTORS,
                PipelineCancelled,
                run_multi_pipeline,
                run_pipeline,
            )
        except ImportError as e:
            self.error.emit(f"Не удалось импортировать ядро: {e}")
            return'''

_OLD_PATCH = '''        # Monkey-patch: DETECTORS и RULES — модульные переменные,
        # _detect() и run_all() читают их при каждом вызове.
        # finally возвращает оригиналы даже при исключении.
        original_detectors = core.DETECTORS
        original_rules = contra_registry.RULES

        if self._disabled_detectors:
            core.DETECTORS = [
                d for d in original_detectors
                if d.name not in self._disabled_detectors
            ]
        if self._disabled_contradictions:
            contra_registry.RULES = [
                r for r in original_rules
                if type(r).__name__ not in self._disabled_contradictions
            ]

        t0 = time.perf_counter()
        try:
            if self._is_multi:
                report = run_multi_pipeline(
                    self._pcap_paths,
                    self._config,
                    should_stop=self.isInterruptionRequested,
                    on_progress=self._emit_progress,
                    on_phase=self._emit_phase,
                )
            else:
                report = run_pipeline(
                    self._pcap_path,
                    self._config,
                    should_stop=self.isInterruptionRequested,
                    on_progress=self._emit_progress,
                    on_phase=self._emit_phase,
                )
        except PipelineCancelled:
            self.cancelled.emit()
            return
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")
            return
        finally:
            core.DETECTORS = original_detectors
            contra_registry.RULES = original_rules
        elapsed = time.perf_counter() - t0'''

_NEW_PATCH = '''        # v1.4: активный список детекторов/правил передаётся параметром,
        # без monkey-patch глобального DETECTORS/RULES. Thread-safe:
        # два параллельных воркера не мутируют одно и то же состояние.
        active_detectors: list | None = None
        if self._disabled_detectors:
            active_detectors = [
                d for d in DETECTORS
                if d.name not in self._disabled_detectors
            ]

        active_rules: list | None = None
        if self._disabled_contradictions:
            active_rules = [
                r for r in RULES
                if type(r).__name__ not in self._disabled_contradictions
            ]

        t0 = time.perf_counter()
        try:
            if self._is_multi:
                report = run_multi_pipeline(
                    self._pcap_paths,
                    self._config,
                    should_stop=self.isInterruptionRequested,
                    on_progress=self._emit_progress,
                    on_phase=self._emit_phase,
                    detectors=active_detectors,
                    rules=active_rules,
                )
            else:
                report = run_pipeline(
                    self._pcap_path,
                    self._config,
                    should_stop=self.isInterruptionRequested,
                    on_progress=self._emit_progress,
                    on_phase=self._emit_phase,
                    detectors=active_detectors,
                    rules=active_rules,
                )
        except PipelineCancelled:
            self.cancelled.emit()
            return
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")
            return
        elapsed = time.perf_counter() - t0'''


def apply(root: Path) -> bool:
    changed = False
    changed |= patch(root, FILES[0], _OLD_IMPORTS, _NEW_IMPORTS)
    changed |= patch(root, FILES[0], _OLD_PATCH, _NEW_PATCH)
    return changed


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], "active_detectors: list | None = None")
    assert_applied(root, FILES[0], "detectors=active_detectors,")
    assert_not_present(root, FILES[0], "core.DETECTORS")
    assert_not_present(root, FILES[0], "contra_registry.RULES")
