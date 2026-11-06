"""GUI: единые роли и футеры диалогов."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_carved_dialog_has_footer_even_without_files(qapp):
    from PySide6.QtWidgets import QDialogButtonBox

    from paradox_gui.dialogs.carved_files_dialog import CarvedFilesDialog

    dlg = CarvedFilesDialog({"carved_files": {"files": []}})
    box = dlg.findChild(QDialogButtonBox)
    assert box is not None
    assert box.button(QDialogButtonBox.StandardButton.Close) is not None


def test_what_if_uses_ok_cancel_button_box(qapp):
    from PySide6.QtWidgets import QDialogButtonBox

    from paradox_gui.dialogs.what_if_dialog import WhatIfDialog

    dlg = WhatIfDialog()
    box = dlg.findChild(QDialogButtonBox)
    assert box is not None
    ok = box.button(QDialogButtonBox.StandardButton.Ok)
    assert ok.objectName() == "primary"
    assert ok.isDefault()
    cancel = box.button(QDialogButtonBox.StandardButton.Cancel)
    assert cancel.autoDefault() is False


def test_finding_dialog_uses_shared_typography(qapp):
    from PySide6.QtWidgets import QLabel

    from paradox_gui.dialogs.finding_dialog import FindingDialog

    dlg = FindingDialog({
        "type": "dns_tunneling",
        "value": "a.b.evil.example",
        "confidence": 0.9,
    })
    names = {w.objectName() for w in dlg.findChildren(QLabel)}
    assert dlg.objectName() == "findingDialog"
    assert "dialogTitle" in names
    assert "sectionLabel" in names


def test_contradiction_dialog_uses_shared_typography(qapp):
    from PySide6.QtWidgets import QLabel

    from paradox_gui.dialogs.contradiction_dialog import ContradictionDialog

    dlg = ContradictionDialog({
        "rule": "sni_mismatch",
        "subject": "10.0.0.5",
        "severity": "high",
        "confidence": 0.8,
    })
    names = {w.objectName() for w in dlg.findChildren(QLabel)}
    assert dlg.objectName() == "contradictionDialog"
    assert "dialogTitle" in names
    assert "sectionLabel" in names
