"""f05: обновить тест broken-detector под новое поведение (f02).

Раньше assert ждал RuntimeError (pipeline падал). Теперь — pipeline
выживает, ошибка считается в extractor_errors["detector:<name>"].
"""
from pathlib import Path

from tools._patcher import assert_applied, patch

NAME = "f05: test_pipeline_deep.py — адаптировать под try/except"
FILES = ["tests/test_pipeline_deep.py"]

_OLD = '''def test_pipeline_extractor_exception_counted(tmp_path):
    """Если детектор падает — pipeline продолжает, а счётчик растёт."""
    pcap = _build_pcap(tmp_path, n=1)
    cfg = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)

    # Мокаем один из детекторов, чтобы он падал
    from paradox import pipeline as pipeline_mod

    original = pipeline_mod.DETECTORS[:]
    class BrokenDetector:
        name = "broken_test_detector"
        def run(self, state, config):
            raise RuntimeError("boom")
    pipeline_mod.DETECTORS = [BrokenDetector()] + original

    try:
        # _detect ловит исключения? Смотрим на pipeline._detect
        # Если нет — ошибка вылетит. Тест проверяет именно поведение.
        # В текущей реализации _detect НЕ ловит → пайплайн упадёт.
        # Тогда тест должен это зафиксировать (или мы увидим AssertionError).
        with pytest.raises(RuntimeError):
            run_pipeline(pcap, cfg)
    finally:
        pipeline_mod.DETECTORS = original'''

_NEW = '''def test_pipeline_broken_detector_counted(tmp_path):
    """Битый детектор не валит pipeline: ошибка считается, findings идут.

    Регрессия: раньше _detect не ловил исключения — один сломанный
    детектор обрушивал весь прогон. v1.4: try/except + счётчик
    в extractor_errors["detector:<name>"].
    """
    pcap = _build_pcap(tmp_path, n=1)
    cfg = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)

    from paradox.pipeline import DETECTORS

    class BrokenDetector:
        name = "broken_test_detector"

        def run(self, state, config):
            raise RuntimeError("boom")

    # Без monkey-patch: список передаётся параметром detectors=.
    broken_list = [BrokenDetector()] + list(DETECTORS)

    report = run_pipeline(pcap, cfg, detectors=broken_list)

    # Ошибка посчитана — с префиксом detector:
    errors = report["summary"]["extractor_errors"]
    assert errors.get("detector:broken_test_detector") == 1

    # Остальные детекторы отработали — структура отчёта цела.
    assert isinstance(report["findings"], list)'''


def apply(root: Path) -> bool:
    return patch(root, FILES[0], _OLD, _NEW)


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], "def test_pipeline_broken_detector_counted(tmp_path):")
