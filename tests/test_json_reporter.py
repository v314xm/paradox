import json
from unittest.mock import patch

from paradox.reporters.json_reporter import write_json, write_markdown


def test_write_json(tmp_path):
    report = {"summary": {"packets": 42}, "findings": []}
    out_file = tmp_path / "out.json"

    write_json(report, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["summary"]["packets"] == 42


@patch("paradox.reporters.markdown_reporter.render_markdown", return_value="# Mocked Markdown")
def test_write_markdown(mock_render, tmp_path):
    report = {
        "provenance": {"pcap_path": "test.pcap", "pcap_sha256": "abc", "tool_version": "1.0"},
        "summary": {"packets": 10, "findings": 0},
        "findings": []
    }
    out_file = tmp_path / "out.md"

    write_markdown(report, out_file)

    assert out_file.read_text(encoding="utf-8") == "# Mocked Markdown"
    assert mock_render.called