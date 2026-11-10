"""GUI: общий стиль контролов и сгенерированные стрелки."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_arrow_assets_are_generated(qapp):
    from pathlib import Path

    from paradox_gui.theme import _arrow_assets, build_qss

    assets = _arrow_assets()
    assert set(assets) == {
        "arrow_down", "arrow_up", "arrow_down_disabled",
    }
    for path in assets.values():
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0

    qss = build_qss(**assets)
    assert "QComboBox::down-arrow" in qss
    assert "QSpinBox::up-arrow" in qss
    assert 'url("' in qss


def test_theme_covers_shared_controls():
    from paradox_gui.theme import QSS

    for selector in (
        "QComboBox::down-arrow",
        "QSpinBox::up-arrow",
        "QRadioButton::indicator",
        "QListWidget::item",
        "QToolButton",
        "QSlider::handle:horizontal",
        "QTableCornerButton::section",
        "QDialogButtonBox QPushButton",
    ):
        assert selector in QSS, selector


def test_dialog_typography_uses_dedicated_roles():
    from paradox_gui.theme import QSS

    assert "QDialog QLabel#h1" not in QSS
    assert "QLabel#dialogTitle" in QSS
    assert "QLabel#sectionTitle" in QSS
    assert "QLabel#sectionLabel" in QSS
