import pytest
from pathlib import Path
from unittest.mock import patch
from paradox.cli import main


@pytest.fixture
def mock_pcap(tmp_path):
    p = tmp_path / "test.pcap"
    p.write_text("fake pcap content")
    return p


@patch("paradox.cli.run_pipeline")
@patch("paradox.cli.write_json")
@patch("paradox.cli.write_markdown")
def test_cli_main_success(mock_md, mock_json, mock_pipeline, mock_pcap, capsys):
    # Мокаем возврат пайплайна
    mock_pipeline.return_value = {
        "summary": {"packets": 100, "unique_dns_queries": 5, "nxdomain_count": 0, "flows": 10, "findings": 2,
                    "extractor_errors": {}},
        "provenance": {"pcap_path": str(mock_pcap)}
    }

    # Запускаем CLI от лица пользователя
    main([str(mock_pcap)])

    # Проверяем, что пайплайн вызвался
    assert mock_pipeline.called
    assert mock_json.called
    assert mock_md.called

    # Проверяем вывод в консоль
    captured = capsys.readouterr()
    assert "packets:            100" in captured.out
    assert "findings:           2" in captured.out


def test_cli_file_not_found(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["non_existent_file.pcap"])
    assert exc.value.code == 2
    assert "file not found" in capsys.readouterr().err