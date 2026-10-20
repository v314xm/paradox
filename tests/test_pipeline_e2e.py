from unittest.mock import patch

from paradox.config import Config
from paradox.pipeline import run_pipeline


@patch("paradox.pipeline.RawPcapReader")
def test_pipeline_full_run(mock_reader, tmp_path):
    # Эмулируем пустой pcap (0 пакетов)
    mock_reader.return_value.__iter__.return_value = iter([])
    mock_reader.return_value.f.tell.return_value = 0

    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # минимальный заголовок

    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    report = run_pipeline(pcap, config)

    # Проверяем структуру отчета
    assert "summary" in report
    assert "findings" in report
    assert "contradictions" in report
    assert "timeline" in report
    assert report["summary"]["packets"] == 0
    assert report["summary"]["findings"] == 0