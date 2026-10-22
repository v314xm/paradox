"""Окно для просмотра извлечённых файлов (Carved Files)."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from paradox_gui.i18n import tr


class CarvedFilesDialog(QDialog):
    def __init__(self, report: dict, parent=None) -> None:
        super().__init__(parent)
        self._report = report
        self.setWindowTitle(tr("carved.title"))
        self.resize(900, 500)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # --- Баннер предупреждения ---
        warn = QFrame()
        warn.setStyleSheet(
            "QFrame { background: #3a1c1c; border: 1px solid #ff5555; "
            "border-radius: 6px; }"
        )
        w_layout = QVBoxLayout(warn)
        w_layout.setContentsMargins(12, 10, 12, 10)
        lbl_warn = QLabel(tr("carved.warning"))
        lbl_warn.setStyleSheet("color: #ff8888; font-size: 13px;")
        lbl_warn.setWordWrap(True)
        w_layout.addWidget(lbl_warn)
        layout.addWidget(warn)

        files = (self._report.get("carved_files") or {}).get("files", [])
        if not files:
            empty = QLabel(tr("carved.empty"))
            empty.setStyleSheet("color: #a0a0b0;")
            layout.addWidget(empty)
            layout.addStretch(1)
            return

        # --- Таблица файлов ---
        self.table = QTableWidget(len(files), 5)
        self.table.setHorizontalHeaderLabels([
            tr("carved.col_sha"), tr("carved.col_ext"),
            tr("carved.col_size"), tr("carved.col_uri"),
            tr("carved.col_status")
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hh = self.table.horizontalHeader()
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
                st_item.setForeground(QBrush(QColor("#50fa7b")))
                self.table.setItem(row, 4, st_item)
            else:
                st_item = QTableWidgetItem(tr("carved.status_meta"))
                st_item.setForeground(QBrush(QColor("#a0a0b0")))
                self.table.setItem(row, 4, st_item)

            self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, f)

        self.table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self.table, stretch=1)

        # --- Кнопки ---
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)

        any_saved = any(
            f.get("saved_path") and Path(f["saved_path"]).exists()
            for f in files
        )
        if any_saved:
            open_dir = QPushButton(tr("carved.open_dir"))
            open_dir.clicked.connect(self._open_dir)
            btn_row.addWidget(open_dir)

        close_btn = QPushButton(tr("carved.close"))
        close_btn.setObjectName("primary")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

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
