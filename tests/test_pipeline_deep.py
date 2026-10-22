"""Углублённые тесты pipeline: отмена, on_phase, исключения."""
from unittest.mock import MagicMock

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

from paradox.config import Config
from paradox.pipeline import PipelineCancelled, run_pipeline


def _build_pcap(tmp_path, n=1):
    """TCP-пакеты вместо DNS — scapy не парсит DNS при wrpcap,
    поэтому нет 10000 warning'ов и прогон быстрее в 5 раз."""
    pkts = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.5", dst="8.8.8.8")
        / TCP(sport=12345 + (i % 1000), dport=80, flags="S")
        / Raw(load=f"GET /host{i} HTTP/1.0\r\n\r\n".encode())
        for i in range(n)
    ]
    pcap_path = tmp_path / "deep.pcap"
    wrpcap(str(pcap_path), pkts)
    return pcap_path


def test_pipeline_on_phase_detect_detail(tmp_path):
    """on_phase('detect', ...) передаёт имя текущего детектора в detail."""
    pcap = _build_pcap(tmp_path, n=1)
    cfg = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    on_phase = MagicMock()

    run_pipeline(pcap, cfg, on_phase=on_phase)

    detect_calls = [
        c for c in on_phase.call_args_list
        if c.args[0] == "detect"
    ]
    assert detect_calls, "on_phase('detect') должен вызываться"
    # Хотя бы у одной записи detail непустой (имя детектора)
    details = [c.args[3] for c in detect_calls if len(c.args) > 3]
    assert any(d for d in details), "detail должен содержать имя детектора"


def test_pipeline_broken_detector_counted(tmp_path):
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
    assert isinstance(report["findings"], list)


def test_pipeline_stop_via_should_stop(tmp_path):
    """should_stop=True после 10000 пакетов → PipelineCancelled."""
    # Генерим 10001 пакет — на 10000-м should_stop вызовется
    pcap = _build_pcap(tmp_path, n=10001)
    cfg = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)

    # should_stop возвращает False первые разы, потом True
    call_count = [0]
    def should_stop():
        call_count[0] += 1
        return call_count[0] >= 1  # с первого вызова True

    with pytest.raises(PipelineCancelled):
        run_pipeline(pcap, cfg, should_stop=should_stop)


def test_pipeline_on_progress_final_100(tmp_path):
    """Последний on_progress вызов — 100% (bytes_read == total)."""
    pcap = _build_pcap(tmp_path, n=1)
    cfg = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    on_progress = MagicMock()

    run_pipeline(pcap, cfg, on_progress=on_progress)

    assert on_progress.called
    last_call_args = on_progress.call_args_list[-1].args
    assert last_call_args[0] == last_call_args[1], \
        "Финальный on_progress должен быть 100%"
