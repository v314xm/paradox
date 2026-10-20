"""QThread-обёртка над run_pipeline.

Ядро синхронное и тяжёлое (десятки секунд на больших pcap). В главном
потоке запускать нельзя — UI замёрзнет. QThread + сигналы — стандарт Qt.

Воркер ничего не знает про виджеты: испускает сигналы, разбираются
подписчики. Так его можно дёргать из теста без QApplication.
"""
import time
from pathlib import Path

from PySide6.QtCore import QThread, Signal


class AnalysisWorker(QThread):
    # object, а не dict — PySide6 не всегда корректно конвертирует
    # контейнерные типы через Signal(dict), object работает всегда.
    finished_ok = Signal(object)
    error = Signal(str)
    cancelled = Signal()
    progress = Signal(int, int)  # bytes_read, total_bytes
    phase = Signal(str, int, int, str)  # phase_name, done, total, detail

    def stop(self) -> None:
        """Кооперативная остановка: requestInterruption.

        run_pipeline проверяет isInterruptionRequested каждые
        10 000 пакетов и бросает PipelineCancelled.
        terminate() не используется — он валил процесс.
        """
        if self.isRunning():
            self.requestInterruption()

    def _emit_progress(self, bytes_read: int, total: int) -> None:
        """Called from the worker thread.

        Qt queued-connection handles cross-thread signal delivery
        safely — GUI thread reads the value in its own slot.
        """
        self.progress.emit(int(bytes_read), int(total))

    def _emit_phase(self, name: str, done: int, total: int,
                    detail: str = "") -> None:
        """Coarse phase ticks: detect / contradictions / report.

        detail — имя текущего детектора для фазы detect, пусто
        для остальных.
        """
        self.phase.emit(str(name), int(done), int(total), str(detail))

    def __init__(
            self,
            pcap_path: str | list[str],
            config,
            disabled_detectors: set[str] | None = None,
            disabled_contradictions: set[str] | None = None,
            parent=None,
    ) -> None:
        super().__init__(parent)
        # v1.2: multi-pcap — принимаем один путь или список
        if isinstance(pcap_path, list):
            self._pcap_paths = [Path(p) for p in pcap_path]
            self._is_multi = True
            self._pcap_path = self._pcap_paths[0]  # для совместимости
        else:
            self._pcap_paths = [Path(pcap_path)]
            self._is_multi = False
            self._pcap_path = self._pcap_paths[0]
        self._config = config
        self._disabled_detectors = disabled_detectors or set()
        self._disabled_contradictions = disabled_contradictions or set()

    def run(self) -> None:
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
            return

        # Monkey-patch: DETECTORS и RULES — модульные переменные,
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
        elapsed = time.perf_counter() - t0

        summary = dict(report.get("summary", {}))
        if "size_bytes" not in summary:
            total_size = 0
            for p in self._pcap_paths:
                try:
                    total_size += p.stat().st_size
                except OSError:
                    pass
            summary["size_bytes"] = total_size
        summary.setdefault("duration_sec", elapsed)
        report["summary"] = summary

        self.finished_ok.emit(report)
