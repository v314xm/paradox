"""Smoke: главное окно собирается, а TAB_TITLES совпадает с вкладками.

`tools/docs_inventory.py` печатает состав GUI по TAB_TITLES, поэтому
список должен совпадать с фактическим порядком вкладок.
"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_builds_and_tab_titles_match(qapp):
    from paradox_gui.main_window import TAB_TITLES, MainWindow

    window = MainWindow()
    try:
        assert window.tabs.count() == len(TAB_TITLES)
        actual = tuple(
            window.tabs.tabText(i) for i in range(window.tabs.count())
        )
        assert actual == TAB_TITLES
        assert len(TAB_TITLES) == 9
    finally:
        window.close()
