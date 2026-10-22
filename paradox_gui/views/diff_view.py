"""Вкладка «Сравнение»: два JSON-отчёта → что изменилось."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.analyzers.run_diff import diff_reports, render_diff_markdown
from paradox_gui.i18n import tr


class DiffView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._old: dict | None = None
        self._new: dict | None = None
        self.setAcceptDrops(True)
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(12)

        title = QLabel(tr("diff.title"))
        title.setObjectName("h1")
        outer.addWidget(title)

        hint = QLabel(tr("diff.subtitle"))
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        outer.addWidget(hint)

        row = QHBoxLayout()
        self._btn_old = QPushButton(tr("diff.load_old"))
        self._btn_old.clicked.connect(lambda: self._load("old"))
        self._lbl_old = QLabel("—")
        self._lbl_old.setObjectName("muted")
        row.addWidget(self._btn_old)
        row.addWidget(self._lbl_old, stretch=1)

        self._btn_new = QPushButton(tr("diff.load_new"))
        self._btn_new.clicked.connect(lambda: self._load("new"))
        self._lbl_new = QLabel("—")
        self._lbl_new.setObjectName("muted")
        row.addWidget(self._btn_new)
        row.addWidget(self._lbl_new, stretch=1)
        outer.addLayout(row)

        self._summary = QLabel(tr("diff.placeholder"))
        self._summary.setObjectName("muted")
        self._summary.setWordWrap(True)
        outer.addWidget(self._summary)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self._btn_export = QPushButton(tr("diff.export_md"))
        self._btn_export.setEnabled(False)
        self._btn_export.clicked.connect(self._on_export_md)
        btn_row.addWidget(self._btn_export)
        outer.addLayout(btn_row)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Категория", "Значение", "Детали"])
        self._tree.setAlternatingRowColors(True)
        self._tree.header().resizeSection(0, 200)
        self._tree.header().resizeSection(1, 400)
        outer.addWidget(self._tree, stretch=1)

    def _load(self, which: str) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть JSON-отчёт", "",
            "JSON (*.json);;Все файлы (*)",
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(self, tr("diff.err_file"), f"{type(e).__name__}: {e}")
            return
        if not isinstance(data, dict) or "findings" not in data:
            QMessageBox.critical(
                self, tr("diff.wrong_file"),
                tr("diff.wrong_file_body"),
            )
            return
        if which == "old":
            self._old = data
            self._lbl_old.setText(Path(path).name)
        else:
            self._new = data
            self._lbl_new.setText(Path(path).name)
        self._refresh()

    def _refresh(self) -> None:
        if not (self._old and self._new):
            return
        d = diff_reports(self._old, self._new)
        self._tree.clear()

        self._summary.setText(self._render_summary(d))

        if d.findings.added:
            top = self._group(f"Новые findings ({len(d.findings.added)})")
            for f in d.findings.added:
                self._leaf(top, f)
        if d.findings.removed:
            top = self._group(f"Исчезли findings ({len(d.findings.removed)})")
            for f in d.findings.removed:
                self._leaf(top, f)
        if d.findings.changed:
            top = self._group(f"Изменились findings ({len(d.findings.changed)})")
            for c in d.findings.changed:
                f = c["new"]
                it = QTreeWidgetItem(top, [
                    str(f.get("type", "?")),
                    str(f.get("value", "")),
                    ", ".join(f"{k}: {o}→{n}" for k, (o, n) in c["changes"].items()),
                ])
                it.setToolTip(1, str(f.get("value", "")))
        if d.contradictions_added:
            top = self._group(f"Новые противоречия ({len(d.contradictions_added)})")
            for c in d.contradictions_added:
                QTreeWidgetItem(top, [
                    str(c.get("rule", "?")),
                    str(c.get("subject", "")),
                    str(c.get("severity", "")),
                ])
        if d.contradictions_removed:
            top = self._group(f"Исчезли противоречия ({len(d.contradictions_removed)})")
            for c in d.contradictions_removed:
                QTreeWidgetItem(top, [
                    str(c.get("rule", "?")),
                    str(c.get("subject", "")),
                    str(c.get("severity", "")),
                ])

        if not d.has_changes():
            self._tree.addTopLevelItem(
                QTreeWidgetItem([tr("diff.no_changes"), "", ""])
            )

        if hasattr(self, "_btn_export"):
            self._btn_export.setEnabled(d.has_changes())

        self._tree.expandAll()

    def _group(self, title: str) -> QTreeWidgetItem:
        it = QTreeWidgetItem(self._tree, [title, "", ""])
        font = it.font(0)
        font.setBold(True)
        it.setFont(0, font)
        return it

    def _leaf(self, parent: QTreeWidgetItem, f: dict) -> None:
        it = QTreeWidgetItem(parent, [
            str(f.get("type", "?")),
            str(f.get("value", "")),
            f"conf={f.get('confidence', 0):.2f}",
        ])
        it.setToolTip(1, str(f.get("value", "")))

    def _render_summary(self, d) -> str:
        parts: list[str] = []
        for field, (ov, nv) in d.summary_changes.items():
            if isinstance(ov, (int, float)) and isinstance(nv, (int, float)):
                delta = nv - ov
                sign = "+" if delta > 0 else ""
                parts.append(f"{field}: {ov}→{nv} ({sign}{delta})")
            else:
                parts.append(f"{field}: {ov}→{nv}")
        base = (
            f"Findings: +{len(d.findings.added)} "
            f"−{len(d.findings.removed)} "
            f"~{len(d.findings.changed)} · "
            f"Противоречий: +{len(d.contradictions_added)} "
            f"−{len(d.contradictions_removed)}"
        )
        if parts:
            base += " · " + " · ".join(parts)
        return base

    def _on_export_md(self) -> None:
        """Сохранить текущий diff в Markdown."""
        if not (self._old and self._new):
            return

        d = diff_reports(self._old, self._new)
        if not d.has_changes():
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить Diff в Markdown", "diff.md",
            "Markdown (*.md);;Все файлы (*)"
        )
        if not path:
            return

        try:
            text = render_diff_markdown(d)
            Path(path).write_text(text, encoding="utf-8")
            QMessageBox.information(
                self, "Успех", f"Diff успешно сохранён:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if not path.lower().endswith('.json'):
            QMessageBox.warning(self, tr("diff.err_file"), tr("diff.expected_json"))
            return

        try:
            data = json.loads(Path(path).read_text(encoding='utf-8'))
        except Exception as e:
            QMessageBox.critical(self, tr("diff.err_file"), f'{e}')
            return

        if not isinstance(data, dict) or 'findings' not in data:
            QMessageBox.critical(self, tr("diff.wrong_file"), tr("diff.not_paradox"))
            return

        # Логика распределения: сначала заполняем старый, потом новый.
        # Если оба заполнены — сдвигаем: старый <- новый, новый <- загруженный.
        if self._old is None:
            self._old = data
            self._lbl_old.setText(Path(path).name)
        elif self._new is None:
            self._new = data
            self._lbl_new.setText(Path(path).name)
        else:
            self._old = self._new
            self._lbl_old.setText(self._lbl_new.text())
            self._new = data
            self._lbl_new.setText(Path(path).name)

        self._refresh()

    def set_reports(self, old: dict | None, new: dict | None) -> None:
        self._old = old
        self._new = new
        self._lbl_old.setText((old or {}).get("provenance", {}).get("pcap_path", "—"))
        self._lbl_new.setText((new or {}).get("provenance", {}).get("pcap_path", "—"))
        self._refresh()
