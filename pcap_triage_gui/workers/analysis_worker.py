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

    def __init__(
            self,
            pcap_path: str,
            config,
            disabled_detectors: set[str] | None = None,
            disabled_contradictions: set[str] | None = None,
            parent=None,
    ) -> None:
        super().__init__(parent)
        self._pcap_path = Path(pcap_path)
        self._config = config
        self._disabled_detectors = disabled_detectors or set()
        self._disabled_contradictions = disabled_contradictions or set()

    def run(self) -> None:
        try:
            import pcap_triage.pipeline as core
            from pcap_triage.pipeline import run_pipeline
            from pcap_triage.contradictions import registry as contra_registry
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
            report = run_pipeline(self._pcap_path, self._config)
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")
            return
        finally:
            core.DETECTORS = original_detectors
            contra_registry.RULES = original_rules
        elapsed = time.perf_counter() - t0

        summary = dict(report.get("summary", {}))
        summary.setdefault("size_bytes", self._pcap_path.stat().st_size)
        summary.setdefault("duration_sec", elapsed)
        report["summary"] = summary

        self.finished_ok.emit(report)