"""GUI: жизненный цикл воркеров без запуска event loop.

Воркеры — QThread, но сигналы эмитятся из того же потока, поэтому
`run()` можно звать напрямую: Qt доставит сигнал слоту синхронно.
"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


# =============================================================================
# AnalysisWorker
# =============================================================================

def _analysis_worker(tmp_path, **kwargs):
    from paradox_gui.workers.analysis_worker import AnalysisWorker

    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"12345")
    return AnalysisWorker(str(pcap), config=object(), **kwargs)


def test_analysis_worker_success(qapp, tmp_path):
    worker = _analysis_worker(tmp_path)
    received = {}
    worker.finished_ok.connect(received.update)

    with patch(
        "paradox.pipeline.run_pipeline",
        return_value={"summary": {"packets": 1}, "findings": []},
    ):
        worker.run()

    assert received["findings"] == []
    assert received["summary"]["packets"] == 1
    assert received["summary"]["size_bytes"] == 5
    assert "duration_sec" in received["summary"]


def test_analysis_worker_cancelled(qapp, tmp_path):
    from paradox.pipeline import PipelineCancelled

    worker = _analysis_worker(tmp_path)
    cancelled = []
    worker.cancelled.connect(lambda: cancelled.append(True))

    with patch(
        "paradox.pipeline.run_pipeline", side_effect=PipelineCancelled(),
    ):
        worker.run()

    assert cancelled == [True]


def test_analysis_worker_reports_exception(qapp, tmp_path):
    worker = _analysis_worker(tmp_path)
    errors = []
    worker.error.connect(errors.append)

    with patch(
        "paradox.pipeline.run_pipeline", side_effect=RuntimeError("boom"),
    ):
        worker.run()

    assert errors == ["RuntimeError: boom"]


def test_analysis_worker_filters_disabled_detectors(qapp, tmp_path):
    worker = _analysis_worker(tmp_path, disabled_detectors={"dga"})
    captured = {}

    def _fake_run(path, config, **kwargs):
        captured.update(kwargs)
        return {"summary": {}, "findings": []}

    with patch("paradox.pipeline.run_pipeline", side_effect=_fake_run):
        worker.run()

    names = [d.name for d in captured["detectors"]]
    assert "dga" not in names
    assert names  # остальные детекторы на месте


# =============================================================================
# QuickCheckWorker
# =============================================================================

class _Provider:
    def __init__(self, name, result=None, boom=False, enabled=True):
        self.name = name
        self.result = result
        self.boom = boom
        self.enabled = enabled
        self.calls = 0

    def lookup(self, ioc, ioc_type):
        self.calls += 1
        if self.boom:
            raise RuntimeError("provider down")
        return self.result


def _result(source, **kwargs):
    from paradox.integrations.base import EnrichmentResult

    return EnrichmentResult(source=source, ioc="1.2.3.4", **kwargs)


def test_quick_check_worker_skips_disabled_and_collects_errors(qapp):
    from paradox_gui.workers.quick_check_worker import QuickCheckWorker

    good = _Provider("good", result=_result("good", data={"score": 1}))
    bad = _Provider("bad", boom=True)
    off = _Provider("off", result=_result("off", data={}), enabled=False)

    worker = QuickCheckWorker("1.2.3.4", "ip", [good, bad, off], cache=None)
    received = {}
    worker.done.connect(received.update)
    worker.run()

    assert set(received) == {"good", "bad"}
    assert received["good"].data == {"score": 1}
    assert received["bad"].error == "provider down"
    assert off.calls == 0


def test_quick_check_worker_uses_cache(qapp):
    from paradox_gui.workers.quick_check_worker import QuickCheckWorker

    cached = _result("cached", data={"from": "cache"})
    provider = _Provider("cached", result=_result("cached", data={}))

    class _Cache:
        def get(self, source, ioc):
            return cached

        def put(self, result):  # pragma: no cover - не должен вызваться
            raise AssertionError("cache.put не нужен при попадании")

    worker = QuickCheckWorker(
        "1.2.3.4", "ip", [provider], cache=_Cache(),
    )
    received = {}
    worker.done.connect(received.update)
    worker.run()

    assert received["cached"] is cached
    assert provider.calls == 0


# =============================================================================
# EnrichmentWorker
# =============================================================================

class _Orchestrator:
    def __init__(self, results):
        self._results = results
        self.stats = {"queries": 1}
        self.closed = False

    def enrich(self, iocs):
        return self._results

    def close(self):
        self.closed = True


def test_enrichment_worker_without_iocs_errors(qapp):
    from paradox_gui.workers.enrichment_worker import EnrichmentWorker

    worker = EnrichmentWorker(report={"findings": []}, config=object(), iocs=[])
    errors = []
    worker.error.connect(errors.append)
    worker.run()

    assert len(errors) == 1
    assert errors[0]


def test_enrichment_worker_keeps_only_ok_results(qapp):
    from paradox_gui.workers.enrichment_worker import EnrichmentWorker

    ok = _result("vt", data={"malicious": 2})
    failed = _result("shodan", error="no key")
    orch = _Orchestrator({("ip", "1.2.3.4"): [ok, failed]})

    worker = EnrichmentWorker(
        report={"findings": []}, config=object(), iocs=[("ip", "1.2.3.4")],
    )
    received = {}
    worker.finished_ok.connect(received.update)

    with (
        patch(
            "paradox.integrations.pipeline.build_default_orchestrator",
            return_value=orch,
        ),
        patch(
            "paradox.integrations.pipeline.attach_enrichment_to_findings",
        ) as attach,
    ):
        worker.run()

    assert received["enrichment"] == {
        ("ip", "1.2.3.4"): {"vt": {"malicious": 2}},
    }
    assert received["stats"]["iocs_total"] == 1
    assert received["stats"]["iocs_enriched"] == 1
    assert attach.called
    assert orch.closed


def test_enrichment_worker_closes_orchestrator_on_error(qapp):
    from paradox_gui.workers.enrichment_worker import EnrichmentWorker

    orch = SimpleNamespace(
        stats={},
        enrich=lambda iocs: (_ for _ in ()).throw(RuntimeError("api down")),
        close=lambda: setattr(orch, "closed", True),
    )
    orch.closed = False

    worker = EnrichmentWorker(
        report={"findings": []}, config=object(), iocs=[("ip", "1.2.3.4")],
    )
    errors = []
    worker.error.connect(errors.append)

    with patch(
        "paradox.integrations.pipeline.build_default_orchestrator",
        return_value=orch,
    ):
        worker.run()

    assert errors == ["RuntimeError: api down"]
    assert orch.closed
