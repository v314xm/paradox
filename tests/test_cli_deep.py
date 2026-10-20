"""Углублённые тесты CLI: _safe_stem, _resolve_output, --enrich."""
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from paradox.cli import _resolve_output, _safe_stem


@dataclass
class _FakeCfg:
    output_dir: Path


def test_safe_stem_replaces_dots():
    """Точки заменяются на подчёркивания."""
    p = Path("snort_log.1425892283.pcap")
    assert _safe_stem(p) == "snort_log_1425892283_pcap"


def test_safe_stem_truncates_to_80():
    """Очень длинное имя обрезается до 80 символов."""
    p = Path("a" * 100 + ".pcap")
    result = _safe_stem(p)
    assert len(result) <= 80


def test_resolve_output_no_arg(tmp_path):
    """out_arg=None → config.output_dir / <stem>.report.json."""
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()

    out = _resolve_output(None, pcap, cfg)

    assert out == tmp_path / "capture_pcap.report.json"
    assert out.parent == tmp_path


def test_resolve_output_existing_dir(tmp_path):
    """out_arg — существующая директория → dir/<stem>.report.json."""
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    out = _resolve_output(out_dir, pcap, cfg)

    assert out == out_dir / "capture_pcap.report.json"


def test_resolve_output_trailing_slash_lost_by_path(tmp_path):
    """Path() теряет trailing slash → treated as file, добавляется .json.

    Известное ограничение: CLI использует type=Path, и к моменту
    _resolve_output слеш уже потерян, поэтому hint не срабатывает.
    Реальное поведение: создаётся файл `newdir.json`, а не `newdir/cap...`.
    """
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()
    out_arg = Path(str(tmp_path / "newdir") + "/")

    out = _resolve_output(out_arg, pcap, cfg)

    # Факт: получаем файл newdir.json, а не папку
    assert out.name == "newdir.json"
    assert out.parent == tmp_path


def test_resolve_output_existing_dir_trailing_slash(tmp_path):
    """Если директория уже существует — она и используется как папка."""
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()
    out_dir = tmp_path / "existing"
    out_dir.mkdir()

    out = _resolve_output(out_dir, pcap, cfg)

    assert out.parent == out_dir
    assert out.name == "capture_pcap.report.json"


def test_resolve_output_file_no_ext(tmp_path):
    """out_arg — файл без расширения → .json добавляется."""
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()
    out_file = tmp_path / "myreport"

    out = _resolve_output(out_file, pcap, cfg)

    assert out == tmp_path / "myreport.json"


def test_resolve_output_file_with_ext(tmp_path):
    """out_arg — файл с расширением → как есть."""
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()
    out_file = tmp_path / "myreport.txt"

    out = _resolve_output(out_file, pcap, cfg)

    assert out == out_file


def test_resolve_output_file_double_ext(tmp_path):
    """out_arg — foo.bar.baz → как есть (не трогаем)."""
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()
    out_file = tmp_path / "foo.bar.baz"

    out = _resolve_output(out_file, pcap, cfg)

    assert out == out_file


def test_resolve_output_creates_parent(tmp_path):
    """Родительская папка создаётся автоматически."""
    cfg = _FakeCfg(output_dir=tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.touch()
    out_file = tmp_path / "deep" / "nested" / "dir" / "report.json"

    out = _resolve_output(out_file, pcap, cfg)

    assert out.parent.is_dir()


# ---- --enrich -------------------------------------------------------------


def test_cli_enrich_flag_success(tmp_path):
    """--enrich вызывает enrich_findings и добавляет stats в report."""
    from paradox.cli import main

    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    out = tmp_path / "out.json"

    fake_report = {
        "summary": {
            "packets": 10, "unique_dns_queries": 0,
            "nxdomain_count": 0, "flows": 1, "findings": 0,
            "extractor_errors": {},
        },
        "provenance": {"pcap_path": str(pcap)},
        "findings": [],
    }

    with patch("paradox.cli.run_pipeline", return_value=fake_report), \
         patch("paradox.cli.write_json"), \
         patch("paradox.cli.write_markdown"), \
         patch("paradox.integrations.pipeline.enrich_findings",
               return_value={"iocs_total": 5, "iocs_enriched": 3,
                             "cache_hits": 1, "provider_calls": 2,
                             "errors": 0}) as mock_enrich:
        main([str(pcap), "-o", str(out), "--enrich"])

    mock_enrich.assert_called_once()
    assert "enrichment_stats" in fake_report
    assert fake_report["enrichment_stats"]["iocs_total"] == 5


def test_cli_enrich_flag_exception_handled(tmp_path):
    """--enrich: если enrich_findings падает, CLI не валится."""
    from paradox.cli import main

    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    out = tmp_path / "out.json"

    fake_report = {
        "summary": {
            "packets": 1, "unique_dns_queries": 0,
            "nxdomain_count": 0, "flows": 0, "findings": 0,
            "extractor_errors": {},
        },
        "provenance": {"pcap_path": str(pcap)},
        "findings": [],
    }

    with patch("paradox.cli.run_pipeline", return_value=fake_report), \
         patch("paradox.cli.write_json"), \
         patch("paradox.cli.write_markdown"), \
         patch("paradox.integrations.pipeline.enrich_findings",
               side_effect=RuntimeError("network down")):
        # Не должен падать
        main([str(pcap), "-o", str(out), "--enrich"])

    assert "enrichment_stats" in fake_report
    assert "error" in fake_report["enrichment_stats"]
