"""Fix #24: _on_compare_history определён дважды в main_window.py."""
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError, assert_applied

FIX_ID = "24-drop-dup-compare-handler"
TITLE = "main_window: убрать дубль _on_compare_history"

REL = "paradox_gui/main_window.py"

_OLD = """            self.tabs.setCurrentIndex(idx)

    def _on_compare_history(self, old_report: dict) -> None:
        \"\"\"Слот на сигнал compare_requested из HistoryView.

        Пользователь выбрал в истории старый прогон и хочет сравнить
        его с тем, что сейчас открыт в RunView.
        \"\"\"
        current_report = self.run_view.last_report()
        if not current_report:
            QMessageBox.information(
                self, "Нет текущего прогона",
                "Сначала выполните анализ pcap во вкладке «Прогон», чтобы "
                "было с чем сравнивать.",
            )
            return

        # Настраиваем DiffView и переключаемся на него
        self.diff_view.set_reports(old_report, current_report)

        # Ищем индекс вкладки DiffView
        idx = self.tabs.indexOf(self.diff_view)
        if idx >= 0:
            self.tabs.setCurrentIndex(idx)"""

_NEW = """            self.tabs.setCurrentIndex(idx)"""


def apply(root: Path) -> bool:
    changed = patch(root, REL, _OLD, _NEW, required=False)
    assert_applied(root, REL, "_on_compare_history")
    if not fix_utils.DRY_RUN:
        n = (root / REL).read_text(encoding="utf-8").count(
            "def _on_compare_history("
        )
        if n != 1:
            raise FixError(f"{REL}: expected 1 def, found {n}")
    return changed