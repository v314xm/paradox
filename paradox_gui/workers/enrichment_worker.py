"""QThread-обёртка над обогащением.

Отличие от простого enrich_findings():
    enrich_findings() собирает IOC сам (все findings разом) — нам это
    не подходит, потому что пользователь выбирает IOC чекбоксами.
    Используем более низкий уровень: build_default_orchestrator() +
    orch.enrich(iocs). Ядро принимает явный список iocs.

После обогащения вызываем attach_enrichment_to_findings — это
прикрепляет результаты к findings в самом report (mutate in-place),
чтобы они попали в JSON-экспорт и в историю.
"""
import time

from PySide6.QtCore import QThread, Signal


class EnrichmentWorker(QThread):
    finished_ok = Signal(object)   # {"stats": {...}, "enrichment": {(type, ioc): {source: data}}}
    error = Signal(str)

    def __init__(self, report: dict, config, iocs: list, parent=None) -> None:
        super().__init__(parent)
        self._report = report
        self._config = config
        # iocs — list[tuple[str, str]] в формате [(type, value), ...]
        self._iocs = list(iocs)

    def run(self) -> None:
        try:
            from paradox.integrations.pipeline import (
                attach_enrichment_to_findings,
                build_default_orchestrator,
            )
        except ImportError as e:
            self.error.emit(f"Не удалось импортировать обогащение: {e}")
            return

        if not self._iocs:
            self.error.emit("Не выбрано ни одного IOC.")
            return

        t0 = time.perf_counter()
        try:
            orch = build_default_orchestrator(self._config)
            try:
                enrichment_map = orch.enrich(self._iocs)

                # Прикрепляем к findings — для JSON-экспорта и истории.
                findings = self._report.get("findings") or []
                attach_enrichment_to_findings(findings, enrichment_map)

                stats = dict(orch.stats)
            finally:
                orch.close()
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")
            return

        # Оставляем только ok-результаты с данными — view отрисовывает
        # ровно то, что есть, без проверок на EnrichmentResult.
        plain: dict = {}
        for key, results in enrichment_map.items():
            per_source = {}
            for r in results:
                if r.ok and r.data:
                    per_source[r.source] = r.data
            if per_source:
                plain[key] = per_source

        stats["iocs_total"] = len(self._iocs)
        stats["iocs_enriched"] = len(plain)
        stats["duration_sec"] = time.perf_counter() - t0
        self.finished_ok.emit({"stats": stats, "enrichment": plain})
