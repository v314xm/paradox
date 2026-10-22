# tools/fix_06_diffview_history.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "06-diffview-history"
TITLE = "DiffView: сравнение записи из Истории с текущим прогоном"
REL_HISTORY = "paradox_gui/views/history_view.py"
REL_MAIN = "paradox_gui/main_window.py"

# --- 1. HistoryView: добавляем сигнал, контекстное меню и парсинг ---

_HIST_IMPORTS_OLD = '''from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)'''

_HIST_IMPORTS_NEW = '''from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)'''

_HIST_CLASS_OLD = '''class HistoryView(QWidget):
    """Список прогонов текущей сессии.

    Публичный API:
        add_run(report)    — добавить успешный прогон (новая запись сверху);
        refresh_current()  — перерисовать выбранную запись (после обогащения);
        clear()            — очистить историю, не трогая текущий прогон.
    """'''

_HIST_CLASS_NEW = '''class HistoryView(QWidget):
    """Список прогонов текущей сессии.

    Публичный API:
        add_run(report)    — добавить успешный прогон (новая запись сверху);
        refresh_current()  — перерисовать выбранную запись (после обогащения);
        clear()            — очистить историю, не трогая текущий прогон.
    """

    # Сигнал для запроса сравнения выбранного прогона с текущим.
    # Передаёт словарь report из истории.
    compare_requested = Signal(object)'''

_HIST_LIST_OLD = '''        self._list = QListWidget()
        self._list.setObjectName("historyList")  # стиль в theme.py
        self._list.setFixedWidth(320)
        # Подписываемся на смену строки сразу при сборке UI. При
        # добавлении первой записи сработает автоматически — не надо
        # вручную вызывать _on_row_changed.
        self._list.currentRowChanged.connect(self._on_row_changed)
        columns.addWidget(self._list)'''

_HIST_LIST_NEW = '''        self._list = QListWidget()
        self._list.setObjectName("historyList")  # стиль в theme.py
        self._list.setFixedWidth(320)
        # Подписываемся на смену строки сразу при сборке UI. При
        # добавлении первой записи сработает автоматически — не надо
        # вручную вызывать _on_row_changed.
        self._list.currentRowChanged.connect(self._on_row_changed)

        # Контекстное меню для сравнения с текущим прогоном
        self._list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._on_context_menu)

        columns.addWidget(self._list)'''

_HIST_CONTEXT_OLD = '''    def _on_row_changed(self, row: int) -> None:
        """Слот на currentRowChanged. Просто перерисовать HTML справа."""'''

_HIST_CONTEXT_NEW = '''    def _on_context_menu(self, pos) -> None:
        """Правый клик по записи: меню действий."""
        item = self._list.itemAt(pos)
        if item is None:
            return

        row = self._list.row(item)
        if row < 0 or row >= len(self._runs):
            return

        _, report, _ = self._runs[row]

        menu = QMenu(self)
        action_compare = menu.addAction("Сравнить с текущим прогоном…")
        action_compare.triggered.connect(lambda: self.compare_requested.emit(report))
        menu.exec(self._list.viewport().mapToGlobal(pos))

    def _on_row_changed(self, row: int) -> None:
        """Слот на currentRowChanged. Просто перерисовать HTML справа."""'''

# --- 2. MainWindow: связываем сигнал ---

_MAIN_TABS_OLD = '''        self.enrich_view.enrichment_finished.connect(
            self._on_enrichment_finished
        )

        self.tabs.addTab(self.run_view, tr("tab.run"))'''

_MAIN_TABS_NEW = '''        self.enrich_view.enrichment_finished.connect(
            self._on_enrichment_finished
        )

        # Сравнение из Истории
        self.history_view.compare_requested.connect(self._on_compare_history)

        self.tabs.addTab(self.run_view, tr("tab.run"))'''

_MAIN_SLOT_OLD = '''    def _on_enrichment_finished(self) -> None:
        """После успешного обогащения — обновить текущую
        запись в «Истории».

        report в истории — тот же объект, что в run_view /
        enrich_view. Обогащение мутирует его in-place.
        QTextBrowser сам не перерисуется, поэтому дёргаем явно.
        """
        if hasattr(self, "history_view"):
            self.history_view.refresh_current()'''

_MAIN_SLOT_NEW = '''    def _on_enrichment_finished(self) -> None:
        """После успешного обогащения — обновить текущую
        запись в «Истории».

        report в истории — тот же объект, что в run_view /
        enrich_view. Обогащение мутирует его in-place.
        QTextBrowser сам не перерисуется, поэтому дёргаем явно.
        """
        if hasattr(self, "history_view"):
            self.history_view.refresh_current()

    def _on_compare_history(self, old_report: dict) -> None:
        """Слот на сигнал compare_requested из HistoryView.

        Пользователь выбрал в истории старый прогон и хочет сравнить
        его с тем, что сейчас открыт в RunView.
        """
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
            self.tabs.setCurrentIndex(idx)'''


def apply(root: Path) -> bool:
    changed = False
    # HistoryView
    if patch(root, REL_HISTORY, _HIST_IMPORTS_OLD, _HIST_IMPORTS_NEW, required=False):
        changed = True
    if patch(root, REL_HISTORY, _HIST_CLASS_OLD, _HIST_CLASS_NEW, required=False):
        changed = True
    if patch(root, REL_HISTORY, _HIST_LIST_OLD, _HIST_LIST_NEW, required=False):
        changed = True
    if patch(root, REL_HISTORY, _HIST_CONTEXT_OLD, _HIST_CONTEXT_NEW, required=False):
        changed = True

    # MainWindow
    if patch(root, REL_MAIN, _MAIN_TABS_OLD, _MAIN_TABS_NEW, required=False):
        changed = True
    if patch(root, REL_MAIN, _MAIN_SLOT_OLD, _MAIN_SLOT_NEW, required=False):
        changed = True

    if not fix_utils.DRY_RUN:
        hist_text = (root / REL_HISTORY).read_text(encoding="utf-8")
        if "compare_requested = Signal" not in hist_text:
            raise FixError(f"{REL_HISTORY}: не удалось применить")

        main_text = (root / REL_MAIN).read_text(encoding="utf-8")
        if "_on_compare_history" not in main_text:
            raise FixError(f"{REL_MAIN}: не удалось применить")

    return changed
