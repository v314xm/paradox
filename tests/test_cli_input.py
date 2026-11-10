"""CLI и границы входа: --version, понятные ошибки формата."""
import pytest

from paradox import __version__
from paradox.cli import main
from paradox.config import Config
from paradox.errors import ParadoxInputError
from paradox.pipeline import run_pipeline


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert f"paradox {__version__}" in capsys.readouterr().out


def test_non_pcap_raises_input_error(tmp_path):
    bad = tmp_path / "notes.txt"
    bad.write_text("this is not a pcap", encoding="utf-8")

    with pytest.raises(ParadoxInputError):
        run_pipeline(bad, Config(file_carve_enabled=False))


def test_pcapng_is_rejected_with_hint(tmp_path):
    pcapng = tmp_path / "capture.pcapng"
    pcapng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)

    with pytest.raises(ParadoxInputError, match="editcap"):
        run_pipeline(pcapng, Config(file_carve_enabled=False))


def test_missing_file_raises_input_error(tmp_path):
    with pytest.raises(ParadoxInputError, match="не найден"):
        run_pipeline(tmp_path / "absent.pcap", Config(file_carve_enabled=False))


def test_truncated_record_raises_input_error(tmp_path):
    """Запись обещает 10 байт, а в файле 3 — это ошибка формата."""
    header = (
        b"\xd4\xc3\xb2\xa1" + (2).to_bytes(2, "little")
        + (4).to_bytes(2, "little") + b"\x00" * 16
    )
    record = (1).to_bytes(4, "little") + b"\x00" * 4 + (10).to_bytes(
        4, "little",
    ) + (10).to_bytes(4, "little") + b"abc"
    pcap = tmp_path / "truncated.pcap"
    pcap.write_bytes(header + record)

    with pytest.raises(ParadoxInputError, match="оборван"):
        run_pipeline(pcap, Config(file_carve_enabled=False))


def test_cli_corrupt_pcap_exits_3(tmp_path, capsys):
    bad = tmp_path / "corrupt.pcap"
    bad.write_bytes(b"garbage")

    with pytest.raises(SystemExit) as exc:
        main([str(bad)])

    assert exc.value.code == 3
    assert "ошибка входа" in capsys.readouterr().err
