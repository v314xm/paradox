"""Список с inline-редактированием.

Структура:
    [поле ввода ______] [Добавить]
    ┌─ список ────────────────┐
    │ 22                      │
    │ 23                      │
    └─────────────────────────┘
    [Удалить выбранное]          ← disabled без выделения
    [Фильтр (N элементов)…]      ← только если >8
    серая подсказка              ← всегда, если задана

API совместим с QPlainTextEdit: setPlainText / toPlainText.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr

PORT_FIELDS = frozenset({
    "suspicious_ports",
    "port_scan_excluded_ports",
    "dc_service_ports",
    "lateral_movement_ports",
    "beaconing_mail_polling_ports",
    "brute_force_skip_tls_ports",
})

_LIST_MIN_H = 100
_LIST_MAX_H = 240
_FILTER_AFTER_N = 8


def _validate_port(text: str) -> bool:
    try:
        p = int(text)
    except ValueError:
        return False
    return 1 <= p <= 65535


class EditableListWidget(QWidget):
    textChanged = Signal()

    def __init__(self, port_mode: bool = False,
                 help_text: str = "", parent=None) -> None:
        super().__init__(parent)
        self._port_mode = port_mode
        self._help_text = help_text
        self._build_ui()
        self._update_visuals()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        # --- row: поле ввода + [Добавить] ---
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        self._input = QLineEdit()
        self._input.setObjectName("listInput")
        self._input.setPlaceholderText(
            tr("list.placeholder.port") if self._port_mode
            else tr("list.placeholder.value")
        )
        self._input.returnPressed.connect(self._add_from_input)
        row.addWidget(self._input)

        self._add_btn = QPushButton(tr("list.add"))
        self._add_btn.setObjectName("primary")
        self._add_btn.setToolTip(tr("list.add_tip"))
        self._add_btn.clicked.connect(self._add_from_input)
        row.addWidget(self._add_btn)

        self._import_btn = QPushButton(tr("list.load"))
        self._import_btn.setObjectName("secondary")
        self._import_btn.setToolTip(tr("list.load_tip"))
        self._import_btn.clicked.connect(self._on_import_clicked)
        row.addWidget(self._import_btn)

        self._export_btn = QPushButton(tr("list.export"))
        self._export_btn.setObjectName("secondary")
        self._export_btn.setToolTip(tr("list.export_tip"))
        self._export_btn.clicked.connect(self._on_export_clicked)
        row.addWidget(self._export_btn)

        row.addStretch(1)
        outer.addLayout(row)

        # --- список ---
        self._list = QListWidget()
        self._list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self._list.setMinimumHeight(_LIST_MIN_H)
        self._list.setMaximumHeight(_LIST_MAX_H)
        self._list.itemChanged.connect(self._on_item_changed)
        self._list.itemSelectionChanged.connect(self._update_delete_btn)
        outer.addWidget(self._list)

        # --- row: [Удалить выбранное] ---
        del_row = QHBoxLayout()
        del_row.setContentsMargins(0, 0, 0, 0)
        del_row.setSpacing(6)

        self._del_btn = QPushButton(tr("list.delete"))
        self._del_btn.setObjectName("dangerOutline")
        self._del_btn.setToolTip(tr("list.delete_tip"))
        self._del_btn.setEnabled(False)
        self._del_btn.clicked.connect(self._remove_selected)
        del_row.addWidget(self._del_btn)
        del_row.addStretch(1)
        outer.addLayout(del_row)

        # --- фильтр (>8 элементов) ---
        self._search = QLineEdit()
        self._search.setObjectName("listFilter")
        self._search.setPlaceholderText(tr("list.placeholder.filter"))
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filter)
        outer.addWidget(self._search)

        # --- hint ---
        self._hint = QLabel(self._help_text)
        self._hint.setObjectName("hint")
        self._hint.setWordWrap(True)
        self._hint.setVisible(bool(self._help_text))
        outer.addWidget(self._hint)

    # -- API ---------------------------------------------------------------

    def items(self) -> list[str]:
        return [self._list.item(i).text() for i in range(self._list.count())]

    def setItems(self, values) -> None:
        self._list.blockSignals(True)
        self._list.clear()
        for v in values:
            self._list.addItem(QListWidgetItem(str(v)))
        self._list.blockSignals(False)
        self._update_visuals()
        self.textChanged.emit()

    def toPlainText(self) -> str:
        return "\n".join(self.items())

    def setPlainText(self, text: str) -> None:
        if not text:
            self.setItems([])
            return
        raw = text.replace(",", "\n").splitlines()
        seen: set[str] = set()
        unique: list[str] = []
        for chunk in raw:
            chunk = chunk.strip()
            if not chunk or chunk.startswith("#"):
                continue
            if chunk in seen:
                continue
            seen.add(chunk)
            unique.append(chunk)
        self.setItems(unique)

    # -- handlers ----------------------------------------------------------

    def _add_from_input(self) -> None:
        text = self._input.text().strip()
        if not text:
            return
        if not self._is_valid(text):
            self._flash_error(tr("list.invalid_port"))
            return
        if text in self.items():
            self._input.clear()
            self._flash_error(tr("list.duplicate"))
            return
        self._list.blockSignals(True)
        self._list.addItem(QListWidgetItem(text))
        self._list.blockSignals(False)
        self._input.clear()
        self._update_visuals()
        self.textChanged.emit()

    def _remove_selected(self) -> None:
        selected = self._list.selectedItems()
        if not selected:
            return
        self._list.blockSignals(True)
        for item in selected:
            self._list.takeItem(self._list.row(item))
        self._list.blockSignals(False)
        self._update_visuals()
        self.textChanged.emit()

    # -- import / export ---------------------------------------------------

    def _on_import_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("list.load_title"), "",
            tr("list.load_filter"),
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            QMessageBox.critical(
                self, tr("list.read_error_title"),
                f"{type(e).__name__}: {e}",
            )
            return

        parsed, skipped = self._parse_import_text(text)
        if not parsed and not skipped:
            QMessageBox.information(
                self, tr("list.empty_title"), tr("list.empty_body"),
            )
            return

        existing = self.items()
        non_dupes = [v for v in parsed if v not in existing]
        dupes = len(parsed) - len(non_dupes)
        if not non_dupes:
            QMessageBox.information(
                self, tr("list.all_present_title"),
                tr("list.all_present_body", count=len(parsed)),
            )
            return

        body = tr("list.import_found", count=len(parsed))
        if dupes:
            body += tr("list.import_dupes", count=dupes)
        if skipped:
            body += tr("list.import_skipped", count=skipped)
        body += tr("list.import_body")
        answer = QMessageBox.question(
            self, tr("list.import_title"), body,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            | QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Cancel:
            return
        if answer == QMessageBox.StandardButton.Yes:
            self.setItems(parsed)
        else:
            self.setItems(existing + non_dupes)

    def _on_export_clicked(self) -> None:
        items = self.items()
        if not items:
            QMessageBox.information(
                self, tr("list.empty_title"), tr("list.nothing_to_save"),
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self, tr("list.save_title"), "list.txt",
            tr("list.load_filter"),
        )
        if not path:
            return
        try:
            Path(path).write_text(
                "\n".join(items) + "\n", encoding="utf-8",
            )
        except OSError as e:
            QMessageBox.critical(
                self, tr("list.write_error_title"),
                f"{type(e).__name__}: {e}",
            )
            return

    def _parse_import_text(self, text: str) -> tuple[list[str], int]:
        """Разобрать текст файла. Вернуть (values, skipped_count).

        Правила: одна строка = один элемент. Пропускаем пустые
        строки и строки, начинающиеся с #. Порт-мод дополнительно
        фильтрует невалидные порты. Дубликаты в файле схлопываются.
        """
        values: list[str] = []
        seen: set[str] = set()
        skipped = 0
        for chunk in text.replace(",", "\n").splitlines():
            chunk = chunk.strip()
            if not chunk or chunk.startswith("#"):
                continue
            if not self._is_valid(chunk):
                skipped += 1
                continue
            if chunk in seen:
                continue
            seen.add(chunk)
            values.append(chunk)
        return values, skipped

    def _on_item_changed(self, _item) -> None:
        self._update_visuals()
        self.textChanged.emit()

    def _update_delete_btn(self) -> None:
        self._del_btn.setEnabled(bool(self._list.selectedItems()))

    def _apply_filter(self, text: str) -> None:
        needle = (text or "").strip().lower()
        for i in range(self._list.count()):
            item = self._list.item(i)
            item.setHidden(bool(needle) and needle not in item.text().lower())

    def _is_valid(self, text: str) -> bool:
        return _validate_port(text) if self._port_mode else bool(text)

    def _update_visuals(self) -> None:
        n = self._list.count()
        show_filter = n > _FILTER_AFTER_N
        self._search.setVisible(show_filter)
        if show_filter:
            self._search.setPlaceholderText(
                tr("list.placeholder.filter_n", n=n)
            )
        else:
            self._search.clear()
        self._update_delete_btn()

    def _flash_error(self, msg: str) -> None:
        self._set_input_invalid(True)
        self._input.setToolTip(msg)

        from PySide6.QtCore import QTimer

        def _reset():
            try:
                self._set_input_invalid(False)
                self._input.setToolTip("")
            except RuntimeError:
                pass

        QTimer.singleShot(1500, _reset)

    def _set_input_invalid(self, invalid: bool) -> None:
        self._input.setProperty("invalid", invalid)
        self._input.style().unpolish(self._input)
        self._input.style().polish(self._input)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace):
            if self._list.hasFocus() and self._list.isVisible():
                self._remove_selected()
                return
        super().keyPressEvent(event)
