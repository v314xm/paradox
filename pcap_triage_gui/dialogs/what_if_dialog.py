"""Диалог для What-If анализа."""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QPlainTextEdit, QPushButton
)
import re

class WhatIfDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("What-If (Исключить)")
        self.resize(400, 300)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Исключить IP-адреса (через запятую или с новой строки):"))
        self.te_ips = QPlainTextEdit()
        self.te_ips.setPlaceholderText("10.0.0.5, 192.168.1.1")
        layout.addWidget(self.te_ips)

        layout.addWidget(QLabel("Исключить домены (частичное совпадение):"))
        self.te_domains = QPlainTextEdit()
        self.te_domains.setPlaceholderText("bad.com, example.org")
        layout.addWidget(self.te_domains)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_apply = QPushButton("Применить")
        btn_apply.setObjectName("primary")
        btn_apply.clicked.connect(self.accept)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_apply)
        layout.addLayout(btn_row)

    def get_exclusions(self) -> tuple[list[str], list[str]]:
        ips_text = self.te_ips.toPlainText().strip()
        domains_text = self.te_domains.toPlainText().strip()

        ips = [i.strip() for i in re.split(r'[\s,]+', ips_text) if i.strip()]
        domains = [d.strip() for d in re.split(r'[\s,]+', domains_text) if d.strip()]

        return ips, domains
