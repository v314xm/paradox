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


def _version_tuple(version: str) -> str:
    return f"({', '.join(version.split('.'))}, 0)"


def test_installer_version_info_matches_pyproject():
    version = _pyproject_version()
    text = (ROOT / "installer" / "version_info.txt").read_text(
        encoding="utf-8",
    )
    expected = _version_tuple(version)
    assert f"filevers={expected}" in text
    assert f"prodvers={expected}" in text
    assert f"u'FileVersion', u'{version}.0'" in text
    assert f"u'ProductVersion', u'{version}.0'" in text


def test_installer_iss_matches_pyproject():
    version = _pyproject_version()
    text = (ROOT / "installer" / "paradox.iss").read_text(
        encoding="utf-8-sig",
    )
    assert f'#define AppVersion "{version}"' in text
    # Без BOM Inno Setup читает © как ANSI-мусор.
    raw = (ROOT / "installer" / "paradox.iss").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")


def test_landing_page_mentions_current_version():
    version = _pyproject_version()
    text = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert f"v{version}" in text
