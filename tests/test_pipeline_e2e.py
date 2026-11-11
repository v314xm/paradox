import hashlib
from unittest.mock import patch

import pytest

from paradox.config import Config
from paradox.pipeline import run_pipeline

pytestmark = pytest.mark.pcap


def _empty_pcap_bytes() -> bytes:
    return (
        b"\xd4\xc3\xb2\xa1"          # magic, little-endian
        + (2).to_bytes(2, "little")   # version major
        + (4).to_bytes(2, "little")   # version minor
        + b"\x00" * 16                # thiszone, sigfigs, snaplen, linktype
    )


def test_pipeline_full_run(tmp_path):
    """Пустой pcap: отчёт собирается, пакетов ноль."""
    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(_empty_pcap_bytes())

    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    report = run_pipeline(pcap, config)

    assert "summary" in report
    assert "findings" in report
    assert "contradictions" in report
    assert "timeline" in report
    assert report["summary"]["packets"] == 0
    assert report["summary"]["findings"] == 0


def test_sha256_is_computed_in_the_parsing_pass(tmp_path):
    """Хэш pcap считается за один проход — второй проход не нужен."""
    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(_empty_pcap_bytes())

    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    with patch("paradox.pipeline.sha256_file") as mock_sha:
        report = run_pipeline(pcap, config)

    mock_sha.assert_not_called()
    assert (
        report["provenance"]["pcap_sha256"]
        == hashlib.sha256(pcap.read_bytes()).hexdigest()
    )


def test_sha256_falls_back_to_second_pass_on_partial_read(tmp_path):
    """Поток прочитан не до конца — инкрементальный хэш неполный."""
    pcap = tmp_path / "partial.pcap"
    pcap.write_bytes(_empty_pcap_bytes())

    class _ReaderStopsEarly:
        """Читатель, который не трогает поток вовсе."""

        bytes_hashed = 0
        complete = False

        def __init__(self, stream):
            self._stream = stream

        def __iter__(self):
            return iter(())

        def hexdigest(self):
            return ""

        def close(self):
            self._stream.close()

    config = Config(tcp_reassembly_enabled=False, file_carve_enabled=False)
    with (
        patch(
            "paradox.pipeline.extract.PcapRecordReader", _ReaderStopsEarly,
        ),
        patch(
            "paradox.pipeline.sha256_file", return_value="fallback-digest",
        ) as mock_sha,
    ):
        report = run_pipeline(pcap, config)

    mock_sha.assert_called_once_with(pcap)
    assert report["provenance"]["pcap_sha256"] == "fallback-digest"
