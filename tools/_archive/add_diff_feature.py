#!/usr/bin/env python3
"""B1: сравнение двух прогонов. Создаёт модули + патчит main_window."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUP = ROOT / ".diff-backup"

FILES = {}

FILES["paradox_gui/analyzers/__init__.py"] = '"""Анализаторы GUI (без Qt-зависимостей)."""\n'

FILES["paradox_gui/analyzers/run_diff.py"] = '''"""
Сравнение двух отчётов run_pipeline.

Чистая логика, без Qt — тестируется независимо.
Ключи для сопоставления:
  findings       → (type, value)
  contradictions → (rule, subject)
Порядок в списках сохраняется — UI не должен мерцать.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class FindingDiff:
    added: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)   # {"old", "new", "changes"}
    unchanged: list[dict] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)


@dataclass
class DiffResult:
    old_meta: dict
    new_meta: dict
    findings: FindingDiff
    contradictions_added: list[dict] = field(default_factory=list)
    contradictions_removed: list[dict] = field(default_factory=list)
    summary_changes: dict[str, tuple] = field(default_factory=dict)

    def has_changes(self) -> bool:
        return bool(
            self.findings.total
            or self.contradictions_added
            or self.contradictions_removed
            or self.summary_changes
        )


def _finding_key(f: dict) -> tuple[str, str]:
    return (str(f.get("type", "")), str(f.get("value", "")))


def _contra_key(c: dict) -> tuple[str, str]:
    return (str(c.get("rule", "")), str(c.get("subject", "")))


_SUMMARY_FIELDS = (
    "packets", "flows", "findings", "contradictions",
    "unique_dns_queries", "nxdomain_count",
    "tcp_streams", "http_objects", "carved_files",
)


def diff_reports(old: dict, new: dict) -> DiffResult:
    """Сравнить два отчёта run_pipeline."""
    old_f = {_finding_key(f): f for f in (old.get("findings") or [])}
    new_f = {_finding_key(f): f for f in (new.get("findings") or [])}

    fdiff = FindingDiff()
    for k, nf in new_f.items():
        if k not in old_f:
            fdiff.added.append(nf)
        else:
            of = old_f[k]
            changes = {}
            for field_name in ("confidence", "severity", "mitre_id"):
                ov = of.get(field_name)
                nv = nf.get(field_name)
                if ov != nv:
                    changes[field_name] = (ov, nv)
            if changes:
                fdiff.changed.append({"old": of, "new": nf, "changes": changes})
            else:
                fdiff.unchanged.append(nf)
    for k, of in old_f.items():
        if k not in new_f:
            fdiff.removed.append(of)

    old_c = {_contra_key(c): c for c in (old.get("contradictions") or [])}
    new_c = {_contra_key(c): c for c in (new.get("contradictions") or [])}
    ca = [c for k, c in new_c.items() if k not in old_c]
    cr = [c for k, c in old_c.items() if k not in new_c]

    old_s = old.get("summary") or {}
    new_s = new.get("summary") or {}
    sdiff: dict[str, tuple] = {}
    for f in _SUMMARY_FIELDS:
        ov, nv = old_s.get(f), new_s.get(f)
        if ov != nv and ov is not None and nv is not None:
            sdiff[f] = (ov, nv)

    return DiffResult(
        old_meta=old.get("provenance") or {},
        new_meta=new.get("provenance") or {},
        findings=fdiff,
        contradictions_added=ca,
        contradictions_removed=cr,
        summary_changes=sdiff,
    )
'''


FILES["paradox_gui/views/diff_view.py"] = '''"""Вкладка «Сравнение»: два JSON-отчёта → что изменилось."""
from __future__ import annotations
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QMessageBox,
    QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from paradox_gui.analyzers.run_diff import diff_reports


class DiffView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._old: dict | None = None
        self._new: dict | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(12)

        title = QLabel("Сравнение прогонов")
        title.setObjectName("h1")
        outer.addWidget(title)

        hint = QLabel(
            "Загрузите два JSON-отчёта (старый и новый) — увидите, что "
            "добавилось, что исчезло, что изменилось. Удобно при повторном "
            "триаже одного и того же pcap через день/неделю."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        outer.addWidget(hint)

        row = QHBoxLayout()
        self._btn_old = QPushButton("Загрузить старый…")
        self._btn_old.clicked.connect(lambda: self._load("old"))
        self._lbl_old = QLabel("—")
        self._lbl_old.setObjectName("muted")
        row.addWidget(self._btn_old)
        row.addWidget(self._lbl_old, stretch=1)

        self._btn_new = QPushButton("Загрузить новый…")
        self._btn_new.clicked.connect(lambda: self._load("new"))
        self._lbl_new = QLabel("—")
        self._lbl_new.setObjectName("muted")
        row.addWidget(self._btn_new)
        row.addWidget(self._lbl_new, stretch=1)
        outer.addLayout(row)

        self._summary = QLabel("Загрузите оба отчёта, чтобы увидеть сравнение.")
        self._summary.setObjectName("muted")
        self._summary.setWordWrap(True)
        outer.addWidget(self._summary)

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
            QMessageBox.critical(self, "Ошибка", f"{type(e).__name__}: {e}")
            return
        if not isinstance(data, dict) or "findings" not in data:
            QMessageBox.critical(
                self, "Не тот файл",
                "Не JSON-отчёт Paradox: нет ключа 'findings'.",
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
                QTreeWidgetItem(["Изменений нет", "", ""])
            )
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

    def set_reports(self, old: dict | None, new: dict | None) -> None:
        self._old = old
        self._new = new
        self._lbl_old.setText((old or {}).get("provenance", {}).get("pcap_path", "—"))
        self._lbl_new.setText((new or {}).get("provenance", {}).get("pcap_path", "—"))
        self._refresh()
'''


FILES["tests/test_run_diff.py"] = '''"""Тесты diff_reports (B1)."""
from paradox_gui.analyzers.run_diff import diff_reports, _finding_key


def _f(type_, value, **kw):
    return {"type": type_, "value": value, **kw}


def _c(rule, subject, **kw):
    return {"rule": rule, "subject": subject, **kw}


def test_empty_reports():
    d = diff_reports({}, {})
    assert d.findings.total == 0
    assert not d.has_changes()


def test_identical_reports_no_changes():
    r = {"findings": [_f("dga", "x.com")], "contradictions": []}
    d = diff_reports(r, r)
    assert d.findings.total == 0
    assert not d.has_changes()


def test_added_finding():
    old = {"findings": [_f("dga", "a.com")]}
    new = {"findings": [_f("dga", "a.com"), _f("beaconing", "1.2.3.4")]}
    d = diff_reports(old, new)
    assert len(d.findings.added) == 1
    assert d.findings.added[0]["type"] == "beaconing"
    assert d.has_changes()


def test_removed_finding():
    old = {"findings": [_f("dga", "a.com"), _f("beaconing", "1.2.3.4")]}
    new = {"findings": [_f("dga", "a.com")]}
    d = diff_reports(old, new)
    assert len(d.findings.removed) == 1
    assert d.findings.removed[0]["type"] == "beaconing"


def test_changed_confidence():
    old = {"findings": [_f("dga", "a.com", confidence=0.5)]}
    new = {"findings": [_f("dga", "a.com", confidence=0.9)]}
    d = diff_reports(old, new)
    assert len(d.findings.changed) == 1
    assert d.findings.changed[0]["changes"]["confidence"] == (0.5, 0.9)
    assert len(d.findings.added) == 0
    assert len(d.findings.removed) == 0


def test_changed_severity():
    old = {"findings": [_f("x", "y", severity="low")]}
    new = {"findings": [_f("x", "y", severity="high")]}
    d = diff_reports(old, new)
    assert len(d.findings.changed) == 1


def test_unchanged_findings():
    r = {"findings": [_f("dga", "a.com", confidence=0.5)]}
    d = diff_reports(r, r)
    assert len(d.findings.unchanged) == 1
    assert d.findings.total == 0


def test_contradictions_added_removed():
    old = {"findings": [], "contradictions": [_c("mac_ip_conflict", "10.0.0.1")]}
    new = {"findings": [], "contradictions": [_c("victim_makes_attack", "10.0.0.2")]}
    d = diff_reports(old, new)
    assert len(d.contradictions_added) == 1
    assert len(d.contradictions_removed) == 1


def test_summary_changes():
    old = {"findings": [], "summary": {"packets": 100, "flows": 10}}
    new = {"findings": [], "summary": {"packets": 150, "flows": 10}}
    d = diff_reports(old, new)
    assert "packets" in d.summary_changes
    assert d.summary_changes["packets"] == (100, 150)
    assert "flows" not in d.summary_changes


def test_finding_key_stable():
    assert _finding_key({"type": "a", "value": "b"}) == ("a", "b")
    assert _finding_key({}) == ("", "")
'''


MAIN_WINDOW_IMPORT = (
    "from paradox_gui.views.diff_view import DiffView\n"
)
MAIN_WINDOW_TAB = (
    '        self.diff_view = DiffView()\n'
    '        self.tabs.addTab(self.diff_view, "Сравнение")\n'
)


def _backup(p: Path) -> None:
    if not p.exists():
        return
    BACKUP.mkdir(parents=True, exist_ok=True)
    dst = BACKUP / p.relative_to(ROOT)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, dst)


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="")
    os.replace(tmp, p)


def _patch_main_window(apply: bool) -> bool:
    p = ROOT / "paradox_gui" / "main_window.py"
    if not p.exists():
        print("  ✗ main_window.py not found")
        return False
    c = p.read_text(encoding="utf-8")
    if "DiffView" in c:
        print("  · main_window.py — already patched")
        return True

    # 1) Импорт — после последнего импорта views
    if "from paradox_gui.views.export_view import ExportView" in c:
        c = c.replace(
            "from paradox_gui.views.export_view import ExportView",
            "from paradox_gui.views.export_view import ExportView\n"
            "from paradox_gui.views.diff_view import DiffView",
            1,
        )
    else:
        print("  ✗ export_view import not found — patch manually")
        return False

    # 2) addTab — после addTab export_view
    tab_anchor = (
        '        self.tabs.addTab(self.export_view, tr("tab_export"))'
    )
    if tab_anchor in c:
        c = c.replace(
            tab_anchor,
            tab_anchor + "\n"
            '        self.diff_view = DiffView()\n'
            '        self.tabs.addTab(self.diff_view, "Сравнение")',
            1,
        )
    else:
        # fallback: после self.tabs.addTab(self.export_view, ...
        import re
        m = re.search(r"self\.tabs\.addTab\(self\.export_view,[^\n]*\n", c)
        if not m:
            print("  ✗ addTab(export_view) not found — patch manually")
            return False
        c = c[:m.end()] + (
            '        self.diff_view = DiffView()\n'
            '        self.tabs.addTab(self.diff_view, "Сравнение")\n'
        ) + c[m.end():]

    if apply:
        _backup(p)
        _write(p, c)
        print("  ✓ main_window.py — patched")
    else:
        print("  · main_window.py — would-patch")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--commit", action="store_true")
    ap.add_argument("--push", action="store_true")
    args = ap.parse_args()

    print("APPLY:" if args.apply else "DRY-RUN:")
    for rel, text in FILES.items():
        p = ROOT / rel
        exists = p.exists()
        if args.apply:
            if exists and p.read_text(encoding="utf-8") == text:
                print(f"  · {rel} — up-to-date")
                continue
            _backup(p)
            _write(p, text)
            print(f"  {'✓' if exists else '+'} {rel} — {'updated' if exists else 'created'}")
        else:
            print(f"  {'·' if exists else '+'} {rel}")

    _patch_main_window(args.apply)

    if not args.apply:
        print("\nRun: python tools/add_diff_feature.py --apply --commit")
        return 0

    if args.commit:
        subprocess.run(
            ["git", "add", "paradox_gui/analyzers", "paradox_gui/views/diff_view.py",
             "paradox_gui/main_window.py", "tests/test_run_diff.py"],
            cwd=ROOT,
        )
        rc = subprocess.run(
            ["git", "commit", "-m",
             "feat(gui): B1 — diff двух прогонов (Сравнение)"],
            cwd=ROOT,
        ).returncode
        print("  ✓ committed" if rc == 0 else "  · nothing to commit")

    if args.push:
        rc = subprocess.run(
            ["git", "push", "origin", "HEAD"], cwd=ROOT,
        ).returncode
        print("  ✓ pushed" if rc == 0 else "  ✗ push failed")

    return 0


if __name__ == "__main__":
    sys.exit(main())
