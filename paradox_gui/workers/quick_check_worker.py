"""QThread: параллельный опрос всех провайдеров."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtCore import QThread, Signal


class QuickCheckWorker(QThread):
    """Опросить провайдеров параллельно.

    results: dict[provider_name, EnrichmentResult]
    """

    done = Signal(dict)       # все результаты
    failed = Signal(str)

    def __init__(self, ioc: str, ioc_type: str, providers: list, cache,
                 parent=None) -> None:
        super().__init__(parent)
        self._ioc = ioc
        self._ioc_type = ioc_type
        self._providers = providers
        self._cache = cache

    def run(self) -> None:
        results: dict = {}
        try:
            with ThreadPoolExecutor(
                max_workers=max(2, len(self._providers)),
            ) as pool:
                futures = {}
                for p in self._providers:
                    if not getattr(p, "enabled", True):
                        continue
                    futures[pool.submit(self._query_one, p)] = p.name

                for fut in as_completed(futures):
                    name = futures[fut]
                    try:
                        results[name] = fut.result()
                    except Exception as e:
                        results[name] = _error_result(name, self._ioc,
                                                     self._ioc_type, str(e))
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")
            return
        self.done.emit(results)

    def _query_one(self, provider):
        # Кэш: сначала туда.
        if self._cache is not None:
            try:
                cached = self._cache.get(provider.name, self._ioc)
                if cached is not None:
                    return cached
            except Exception:
                pass

        result = provider.lookup(self._ioc, self._ioc_type)

        if self._cache is not None and result.ok:
            try:
                self._cache.put(result)
            except Exception:
                pass
        return result


def _error_result(source: str, ioc: str, ioc_type: str, msg: str):
    import time

    from paradox.integrations.base import EnrichmentResult
    return EnrichmentResult(
        source=source, ioc=ioc, ioc_type=ioc_type,
        error=msg, fetched_at=time.time(), ttl_days=0,
    )
