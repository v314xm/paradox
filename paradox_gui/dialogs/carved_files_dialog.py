"""Окно для просмотра извлечённых файлов (Carved Files)."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHeaderView,
    QLabel,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from paradox_gui.i18n import tr
from paradox_gui.theme import PALETTE


class CarvedFilesDialog(QDialog):
    def __init__(self, report: dict, parent=None) -> None:
        super().__init__(parent)
        self._report = report
        self.setObjectName("carvedFilesDialog")
        self.setWindowTitle(tr("carved.title"))
        self.resize(900, 520)
        self.setMinimumSize(720, 400)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # --- Баннер предупреждения ---
        warn = QFrame()
        warn.setObjectName("warnBanner")
        w_layout = QVBoxLayout(warn)
        w_layout.setContentsMargins(12, 10, 12, 10)
        lbl_warn = QLabel(tr("carved.warning"))
        lbl_warn.setObjectName("warnText")
        lbl_warn.setWordWrap(True)
        w_layout.addWidget(lbl_warn)
        layout.addWidget(warn)

        files = (self._report.get("carved_files") or {}).get("files", [])
        if not files:
            empty = QLabel(tr("carved.empty"))
            empty.setObjectName("muted")
            layout.addWidget(empty)
            layout.addStretch(1)
            self._add_footer(layout, any_saved=False)
            return

        # --- Таблица файлов ---
        self.table = QTableWidget(len(files), 5)
        self.table.setObjectName("carvedTable")
        self.table.setHorizontalHeaderLabels([
            tr("carved.col_sha"), tr("carved.col_ext"),
            tr("carved.col_size"), tr("carved.col_uri"),
            tr("carved.col_status")
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        hh = self.table.horizontalHeader()
        hh.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        for row, f in enumerate(files):
            sha = f.get("sha256", "")
            ext = f.get("ext", "?")
            size = f.get("size", 0)
            uri = f.get("uri", "")
            saved = f.get("saved_path")

            self.table.setItem(row, 0, QTableWidgetItem(sha))
            self.table.setItem(row, 1, QTableWidgetItem(ext))
            self.table.setItem(row, 2, QTableWidgetItem(str(size)))
            self.table.setItem(row, 3, QTableWidgetItem(uri or "—"))

            if saved and Path(saved).exists():
                st_item = QTableWidgetItem(tr("carved.status_saved"))
                st_item.setForeground(QBrush(QColor(PALETTE["success"])))
                self.table.setItem(row, 4, st_item)
            else:
                st_item = QTableWidgetItem(tr("carved.status_meta"))
                st_item.setForeground(QBrush(QColor(PALETTE["text_muted"])))
                self.table.setItem(row, 4, st_item)

            self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, f)

        self.table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self.table, stretch=1)

        any_saved = any(
            f.get("saved_path") and Path(f["saved_path"]).exists()
            for f in files
        )
        self._add_footer(layout, any_saved=any_saved)

    def _add_footer(self, layout: QVBoxLayout, any_saved: bool) -> None:
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        box.setObjectName("dialogButtons")
        open_dir = box.addButton(
            tr("carved.open_dir"), QDialogButtonBox.ButtonRole.ActionRole
        )
        open_dir.setObjectName("secondary")
        open_dir.setEnabled(any_saved)
        open_dir.clicked.connect(self._open_dir)

        close = box.button(QDialogButtonBox.StandardButton.Close)
        close.setText(tr("carved.close"))
        close.setDefault(True)
        box.rejected.connect(self.accept)
        layout.addWidget(box)

    def _on_double_click(self, index) -> None:
        item = self.table.item(index.row(), 0)
        if item is None:
            return
        f = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(f, dict):
            return
        saved = f.get("saved_path")
        if saved and Path(saved).exists():
            QDesktopServices.openUrl(
                Path(saved).as_uri()
            )
        else:
            QMessageBox.information(
                self, tr("carved.not_saved_title"),
                tr("carved.not_saved_body"),
            )

    def _open_dir(self) -> None:
        files = (self._report.get("carved_files") or {}).get("files", [])
        for f in files:
            saved = f.get("saved_path")
            if saved and Path(saved).exists():
                # Открываем папку, в которой лежит первый найденный файл
                folder = Path(saved).parent
                QDesktopServices.openUrl(folder.as_uri())
                return
