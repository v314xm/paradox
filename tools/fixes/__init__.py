"""Реестр фиксов. Порядок = порядок применения.

Ленивая загрузка через import_module: если какой-то файл отсутствует
или падает при импорте — получим ImportError с точным именем модуля
и исходным исключением, а не generic «circular import».
"""
from __future__ import annotations

from importlib import import_module

_FIX_NAMES = (
    "f01_drop_dead_tests",
    "f02_pipeline_detectors_rules",
    "f03_registry_rules",
    "f04_worker_no_monkeypatch",
    "f05_pipeline_broken_test",
    "f06_timeline_yara",
    "f07_markdown_yara",
    "f08_enricher_rate_counter",
    "f09_special_ip_heuristic",
    "f10_skip_manual_test",
)


def _load_all():
    modules = []
    for name in _FIX_NAMES:
        try:
            mod = import_module(f"tools.fixes.{name}")
        except Exception as e:
            raise ImportError(
                f"cannot load tools.fixes.{name}: "
                f"{type(e).__name__}: {e}"
            ) from e
        modules.append(mod)
    return modules


ALL_FIXES = _load_all()
