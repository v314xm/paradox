# tools/fix_07_diff_to_markdown.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "07-diff-to-markdown"
TITLE = "DiffView: экспорт сравнения в Markdown"
REL_CORE = "paradox_gui/analyzers/run_diff.py"
REL_VIEW = "paradox_gui/views/diff_view.py"

# --- 1. Добавляем render_diff_markdown в run_diff.py ---

_CORE_OLD = '''    return DiffResult(
        old_meta=old.get("provenance") or {},
        new_meta=new.get("provenance") or {},
        findings=fdiff,
        contradictions_added=ca,
        contradictions_removed=cr,
        summary_changes=sdiff,
    )
'''

_CORE_NEW = '''    return DiffResult(
        old_meta=old.get("provenance") or {},
        new_meta=new.get("provenance") or {},
        findings=fdiff,
        contradictions_added=ca,
        contradictions_removed=cr,
        summary_changes=sdiff,
    )


def render_diff_markdown(d: DiffResult) -> str:
    """Сформировать Markdown-отчёт о различиях."""
    from pathlib import Path

    old_name = Path(d.old_meta.get("pcap_path") or "?").name
    new_name = Path(d.new_meta.get("pcap_path") or "?").name

    lines: list[str] = []
    lines.append(f"# Diff: `{old_name}` → `{new_name}`\\n")
    lines.append(
        f"**Findings:** +{len(d.findings.added)} "
        f"−{len(d.findings.removed)} "
        f"~{len(d.findings.changed)}\\n"
    )
    if d.contradictions_added or d.contradictions_removed:
        lines.append(
            f"**Противоречия:** +{len(d.contradictions_added)} "
            f"−{len(d.contradictions_removed)}\\n"
        )

    if d.summary_changes:
        lines.append("## Изменения в сводке")
        lines.append("| Поле | Было | Стало | Дельта |")
        lines.append("|---|---|---|---|")
        for f, (ov, nv) in d.summary_changes.items():
            delta = ""
            if isinstance(ov, (int, float)) and isinstance(nv, (int, float)):
                diff = nv - ov
                delta = f"+{diff}" if diff > 0 else str(diff)
            lines.append(f"| {f} | {ov} | {nv} | {delta} |")
        lines.append("")

    if d.findings.added:
        lines.append("## Новые findings")
        lines.append("| Тип | Значение | Conf |")
        lines.append("|---|---|---|")
        for f in d.findings.added:
            lines.append(
                f"| `{f.get('type', '?')}` | {f.get('value', '')} "
                f"| {f.get('confidence', 0):.2f} |"
            )
        lines.append("")

    if d.findings.removed:
        lines.append("## Исчезли findings")
        lines.append("| Тип | Значение | Conf |")
        lines.append("|---|---|---|")
        for f in d.findings.removed:
            lines.append(
                f"| `{f.get('type', '?')}` | {f.get('value', '')} "
                f"| {f.get('confidence', 0):.2f} |"
            )
        lines.append("")

    if d.findings.changed:
        lines.append("## Изменились findings")
        lines.append("| Тип | Значение | Изменения |")
        lines.append("|---|---|---|")
        for c in d.findings.changed:
            f = c["new"]
            changes_str = ", ".join(
                f"{k}: {o}→{n}" for k, (o, n) in c["changes"].items()
            )
            lines.append(
                f"| `{f.get('type', '?')}` | {f.get('value', '')} "
                f"| {changes_str} |"
            )
        lines.append("")

    if d.contradictions_added:
        lines.append("## Новые противоречия")
        lines.append("| Rule | Subject | Severity |")
        lines.append("|---|---|---|")
        for c in d.contradictions_added:
            lines.append(
                f"| `{c.get('rule', '?')}` | `{c.get('subject', '')}` "
                f"| {c.get('severity', '')} |"
            )
        lines.append("")

    if d.contradictions_removed:
        lines.append("## Исчезли противоречия")
        lines.append("| Rule | Subject | Severity |")
        lines.append("|---|---|---|")
        for c in d.contradictions_removed:
            lines.append(
                f"| `{c.get('rule', '?')}` | `{c.get('subject', '')}` "
                f"| {c.get('severity', '')} |"
            )
        lines.append("")

    if not d.has_changes():
        lines.append("_Изменений нет._\\n")

    return "\\n".join(lines)
'''

# --- 2. Модификации в diff_view.py ---

_VIEW_IMPORTS_OLD = '''from paradox_gui.analyzers.run_diff import diff_reports'''

_VIEW_IMPORTS_NEW = '''from paradox_gui.analyzers.run_diff import diff_reports, render_diff_markdown'''

_VIEW_BUTTONS_OLD = '''        self._summary = QLabel("Загрузите оба отчёта, чтобы увидеть сравнение.")
        self._summary.setObjectName("muted")
        self._summary.setWordWrap(True)
        outer.addWidget(self._summary)
'''

_VIEW_BUTTONS_NEW = '''        self._summary = QLabel("Загрузите оба отчёта, чтобы увидеть сравнение.")
        self._summary.setObjectName("muted")
        self._summary.setWordWrap(True)
        outer.addWidget(self._summary)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self._btn_export = QPushButton("Экспорт в Markdown…")
        self._btn_export.setEnabled(False)
        self._btn_export.clicked.connect(self._on_export_md)
        btn_row.addWidget(self._btn_export)
        outer.addLayout(btn_row)
'''

_VIEW_REFRESH_OLD = '''        if not d.has_changes():
            self._tree.addTopLevelItem(
                QTreeWidgetItem(["Изменений нет", "", ""])
            )
        self._tree.expandAll()
'''

_VIEW_REFRESH_NEW = '''        if not d.has_changes():
            self._tree.addTopLevelItem(
                QTreeWidgetItem(["Изменений нет", "", ""])
            )

        if hasattr(self, "_btn_export"):
            self._btn_export.setEnabled(d.has_changes())

        self._tree.expandAll()
'''

_VIEW_SUMMARY_OLD = '''        if parts:
            base += " · " + " · ".join(parts)
        return base

    def dragEnterEvent(self, event) -> None:
'''

_VIEW_SUMMARY_NEW = '''        if parts:
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
                self, "Успех", f"Diff успешно сохранён:\\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def dragEnterEvent(self, event) -> None:
'''


def apply(root: Path) -> bool:
    changed = False
    # run_diff.py
    if patch(root, REL_CORE, _CORE_OLD, _CORE_NEW, required=False):
        changed = True
    # diff_view.py
    if patch(root, REL_VIEW, _VIEW_IMPORTS_OLD, _VIEW_IMPORTS_NEW, required=False):
        changed = True
    if patch(root, REL_VIEW, _VIEW_BUTTONS_OLD, _VIEW_BUTTONS_NEW, required=False):
        changed = True
    if patch(root, REL_VIEW, _VIEW_REFRESH_OLD, _VIEW_REFRESH_NEW, required=False):
        changed = True
    if patch(root, REL_VIEW, _VIEW_SUMMARY_OLD, _VIEW_SUMMARY_NEW, required=False):
        changed = True

    if not fix_utils.DRY_RUN:
        core_text = (root / REL_CORE).read_text(encoding="utf-8")
        if "def render_diff_markdown" not in core_text:
            raise FixError(f"{REL_CORE}: не удалось применить")

        view_text = (root / REL_VIEW).read_text(encoding="utf-8")
        if "_on_export_md" not in view_text:
            raise FixError(f"{REL_VIEW}: не удалось применить")

    return changed
