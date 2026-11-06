"""
Версия должна совпадать в трёх местах: pyproject, ядро, GUI.

Расхождение уже случалось: `paradox_gui/__init__.py` оставался 1.3.0,
пока ядро было 1.4.0, а метаданные editable-установки — 1.0.0.
"""
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    data = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
    )
    return data["project"]["version"]


def test_core_version_matches_pyproject():
    import paradox

    assert paradox.__version__ == _pyproject_version()


def test_gui_version_matches_pyproject():
    import paradox_gui

    assert paradox_gui.__version__ == _pyproject_version()
