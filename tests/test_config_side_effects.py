"""Config не должен трогать файловую систему в конструкторе."""
from pathlib import Path

from paradox.config import Config


def test_config_construction_does_not_create_output_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    Config()

    assert not Path("reports").exists()
