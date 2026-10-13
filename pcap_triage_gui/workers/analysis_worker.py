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

    def __init__(self, pcap_path: str, config, parent=None) -> None:
        super().__init__(parent)
        self._pcap_path = Path(pcap_path)
        self._config = config

    def run(self) -> None:
        # Импорт внутри run, а не на уровне модуля: если ядро упадёт
        # при импорте, GUI не будет падать целиком при старте — только
        # конкретный прогон.
        try:
            from pcap_triage.pipeline import run_pipeline
        except ImportError as e:
            self.error.emit(f"Не удалось импортировать ядро: {e}")
            return

        t0 = time.perf_counter()
        try:
            report = run_pipeline(self._pcap_path, self._config)
        except Exception as e:
            # Ловим всё: воркер живёт в своём потоке, необработанное
            # исключение уронит приложение без следа.
            self.error.emit(f"{type(e).__name__}: {e}")
            return
        elapsed = time.perf_counter() - t0

        # Дополняем summary тем, чего в ядре нет.
        # setdefault, а не присваивание: если ядро когда-нибудь начнёт
        # отдавать size_bytes само — не затрём.
        summary = dict(report.get("summary", {}))
        summary.setdefault("size_bytes", self._pcap_path.stat().st_size)
        summary.setdefault("duration_sec", elapsed)
        report["summary"] = summary

        self.finished_ok.emit(report)