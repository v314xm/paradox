"""Окно TLS-сертификатов из захвата: кто кому что предъявил."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from paradox_gui.i18n import tr


def _date(value) -> str:
    """ISO из отчёта → короткая дата; иначе как есть."""
    text = str(value or "")
    return text[:10] if len(text) >= 10 else text


class CertificatesDialog(QDialog):
    def __init__(self, report: dict, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("certificatesDialog")
        self.setWindowTitle(tr("certs.title"))
        self.resize(960, 520)
        self.setMinimumSize(720, 400)
        self._build_ui(report)

    def _build_ui(self, report: dict) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        certs = report.get("certificates") or {}
        items = [
            item for item in (certs.get("items") or [])
            if isinstance(item, dict)
        ]

        subtitle = QLabel(tr(
            "certs.subtitle",
            total=int(certs.get("total") or len(items)),
            errors=int(certs.get("parse_errors") or 0),
        ))
        subtitle.setObjectName("hint")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        if not items:
            empty = QLabel(tr("certs.empty"))
            empty.setObjectName("muted")
            layout.addWidget(empty)
            layout.addStretch(1)
        else:
            self.table = self._make_table(items)
            layout.addWidget(self.table, stretch=1)

        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        box.setObjectName("dialogButtons")
        close = box.button(QDialogButtonBox.StandardButton.Close)
        close.setText(tr("certs.close"))
        close.setDefault(True)
        box.rejected.connect(self.accept)
        layout.addWidget(box)

    @staticmethod
    def _make_table(items: list[dict]) -> QTableWidget:
        headers = [
            tr("certs.col.host"), tr("certs.col.subject"),
            tr("certs.col.issuer"), tr("certs.col.valid"),
            tr("certs.col.self_signed"),
        ]
        table = QTableWidget(len(items), len(headers))
        table.setObjectName("certificatesTable")
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        table.setAlternatingRowColors(True)

        header = table.horizontalHeader()
        header.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        for column in (0, 3, 4):
            header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        for column in (1, 2):
            header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.Stretch
            )

        for row, item in enumerate(items):
            src = item.get("src_ip") or "?"
            dst = item.get("dst_ip") or "?"
            port = item.get("dst_port")
            host = f"{src} → {dst}:{port}" if port else f"{src} → {dst}"
            subject = str(item.get("subject_cn") or "—")
            issuer = str(item.get("issuer_cn") or "—")
            valid_from = _date(item.get("not_before"))
            valid_to = _date(item.get("not_after"))
            valid = " → ".join(v for v in (valid_from, valid_to) if v) or "—"
            self_signed = (
                tr("certs.yes") if item.get("self_signed")
                else tr("certs.no")
            )

            subject_item = QTableWidgetItem(subject)
            sans = list(item.get("san_dns") or []) + list(
                item.get("san_ips") or []
            )
            if sans:
                subject_item.setToolTip("\n".join(str(s) for s in sans))

            table.setItem(row, 0, QTableWidgetItem(host))
            table.setItem(row, 1, subject_item)
            table.setItem(row, 2, QTableWidgetItem(issuer))
            table.setItem(row, 3, QTableWidgetItem(valid))
            table.setItem(row, 4, QTableWidgetItem(self_signed))
        return table
