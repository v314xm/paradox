"""Диалог для What-If анализа."""
import re

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
)

from paradox_gui.i18n import tr


class WhatIfDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("whatIfDialog")
        self.setWindowTitle(tr("what_if.title"))
        self.resize(560, 420)
        self.setMinimumSize(480, 360)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        ips_lbl = QLabel(tr("what_if.ips_label"))
        ips_lbl.setObjectName("fieldLabel")
        ips_lbl.setWordWrap(True)
        layout.addWidget(ips_lbl)

        self.te_ips = QPlainTextEdit()
        self.te_ips.setObjectName("whatIfInput")
        self.te_ips.setPlaceholderText("10.0.0.5, 192.168.1.1")
        layout.addWidget(self.te_ips)

        domains_lbl = QLabel(tr("what_if.domains_label"))
        domains_lbl.setObjectName("fieldLabel")
        domains_lbl.setWordWrap(True)
        layout.addWidget(domains_lbl)

        self.te_domains = QPlainTextEdit()
        self.te_domains.setObjectName("whatIfInput")
        self.te_domains.setPlaceholderText("bad.com, example.org")
        layout.addWidget(self.te_domains)

        box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        box.setObjectName("dialogButtons")
        ok = box.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText(tr("what_if.apply"))
        ok.setObjectName("primary")
        ok.setDefault(True)
        cancel = box.button(QDialogButtonBox.StandardButton.Cancel)
        cancel.setText(tr("what_if.cancel"))
        cancel.setAutoDefault(False)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        layout.addWidget(box)

    def get_exclusions(self) -> tuple[list[str], list[str]]:
        ips_text = self.te_ips.toPlainText().strip()
        domains_text = self.te_domains.toPlainText().strip()

        ips = [i.strip() for i in re.split(r'[\s,]+', ips_text) if i.strip()]
        domains = [d.strip() for d in re.split(r'[\s,]+', domains_text) if d.strip()]

        return ips, domains
