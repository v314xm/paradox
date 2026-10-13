"""Вкладка «Прогон».

Цепочка: drop zone → QThread(worker) → run_pipeline → report →
summary grid + секция противоречий + (скоро) таблица findings.

=============================================================================
 КАРТА ВСТАВОК
=============================================================================

 Импорты сверху:      по мере появления новых виджетов (findings_table,
                      progress_bar, toast).

 __init__:            новые поля состояния, если появятся.

 _build_ui:           порядок блоков сверху вниз = порядок в GUI.
                      Маркеры >>> МЕСТО ДЛЯ ... <<< показывают, куда
                      вставлять новые виджеты.

 handlers:            сгруппированы: прогон → результаты → детали →
                      ошибки → управление busy.

 API для меню:        слоты, которые дёргает main_window.

 ПРАВИЛО: если в этой вкладке нужен новый виджет — сначала импорт,
 потом место в _build_ui по маркеру, потом обработчик в handlers.
=============================================================================
"""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel, QMessageBox, QVBoxLayout, QWidget

# >>> ИМПОРТЫ ВИДЖЕТОВ <<<
from pcap_triage_gui.dialogs.contradiction_dialog import ContradictionDialog
from pcap_triage_gui.widgets.contradictions_section import ContradictionsSection
from pcap_triage_gui.widgets.drop_zone import DropZone
from pcap_triage_gui.widgets.summary_grid import SummaryGrid
from PySide6.QtWidgets import QProgressBar
from pcap_triage_gui.widgets.toast import ToastManager
# Шаг 7:  from pcap_triage_gui.widgets.findings_table import FindingsTable
# Шаг 11: from pcap_triage_gui.widgets.toast import Toast
# >>> /ИМПОРТЫ ВИДЖЕТОВ <<<
from pcap_triage_gui.dialogs.finding_dialog import FindingDialog
from pcap_triage_gui.widgets.findings_table import FindingsTable
from pcap_triage_gui.workers.analysis_worker import AnalysisWorker


class RunView(QWidget):
    # >>> СИГНАЛЫ НАРУЖУ <<<
    # Подписаны в main_window (статус-бар) и в будущих views (история).
    analysis_started = Signal(str)     # путь
    analysis_finished = Signal(object) # report
    analysis_failed = Signal(str)
    # >>> /СИГНАЛЫ НАРУЖУ <<<

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # >>> СОСТОЯНИЕ <<<
        self._worker: AnalysisWorker | None = None
        self._current_path: str | None = None
        # self._last_report: dict | None = None   # если понадобится для истории
        # >>> /СОСТОЯНИЕ <<<
        self._build_ui()
        self.toasts = ToastManager(self)

    # =========================================================================
    # UI
    # =========================================================================

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # --- Drop zone ---
        self.drop_zone = DropZone()
        self.drop_zone.pcap_selected.connect(self._on_pcap_selected)
        layout.addWidget(self.drop_zone)

        # >>> МЕСТО ДЛЯ PROGRESS BAR (шаг 8-ext) <<<
        # --- Progress bar ---
        # Indeterminate (setRange(0,0)): точный процент требует правки
        # ядра (_extract пишет в stdout, не в callback). Бегающая полоска
        # снимает ощущение зависшего окна при 10-минутных прогонах.
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        # self.progress = QProgressBar()
        # self.progress.setRange(0, 0)
        # self.progress.setVisible(False)
        # layout.addWidget(self.progress)
        # >>> /PROGRESS BAR <<<

        # --- Summary grid: 6 плиток ---
        self.summary = SummaryGrid()
        layout.addWidget(self.summary)

        # --- Секция противоречий ---
        self.contradictions = ContradictionsSection()
        self.contradictions.details_requested.connect(self._on_contra_details)
        layout.addWidget(self.contradictions)

        # --- Таблица findings ---
        # stretch=1 — секция забирает всё свободное место.
        self.findings = FindingsTable()
        self.findings.row_activated.connect(self._on_finding_details)
        layout.addWidget(self.findings, stretch=1)

        # >>> МЕСТО ДЛЯ ДРУГИХ СЕКЦИЙ <<<
        # >>> /ДРУГИЕ СЕКЦИИ <<<

        # --- Статус-строка внизу вкладки ---
        self.status_label = QLabel("Файл не выбран.")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)

        # НЕТ addStretch(1) — findings уже растянут



    # =========================================================================
    # HANDLERS — запуск прогона
    # =========================================================================

    def _on_pcap_selected(self, path: str) -> None:
        # Второй файл поверх идущего анализа игнорируем — не хотим
        # конкурирующих воркеров и мусора в summary.
        if self._worker and self._worker.isRunning():
            return

        self._current_path = path
        self._reset_results()
        self._run_analysis()

    def _run_analysis(self) -> None:
        if not self._current_path:
            return
        try:
            from pcap_triage.config import Config
            config = Config()
        except ImportError as e:
            self._on_error(f"Не удалось импортировать Config: {e}")
            return

        self._set_busy(True)
        self.status_label.setText(f"Анализ: {self._current_path}")

        self._worker = AnalysisWorker(self._current_path, config)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_thread_done)
        self._worker.start()
        self.analysis_started.emit(self._current_path)

    # =========================================================================
    # HANDLERS — результаты прогона
    # =========================================================================

    def _on_ok(self, report: dict) -> None:
        s = report.get("summary", {})
        self.summary.set_values(s)
        self.contradictions.set_contradictions(report.get("contradictions", []))

        # >>> ЗАПОЛНЕНИЕ ДРУГИХ СЕКЦИЙ <<<

        # Шаг 7:  self.findings.set_findings(report.get("findings", []))
        # >>> /ЗАПОЛНЕНИЕ ДРУГИХ СЕКЦИЙ <<<
        self.findings.set_findings(report.get("findings", []))
        self.status_label.setText(
            f"Готово · {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий · "
            f"{s.get('duration_sec', 0):.1f} сек"
        )
        self.toasts.show(
            f"Готово: {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий",
            "success",
        )
        self.analysis_finished.emit(report)
        # Компактный drop zone после успешного прогона — освобождает
        # место для таблицы findings. Файл уже проанализирован,
        # большая зона «Перетащите pcap сюда» больше не нужна.
        if self._current_path:
            self.drop_zone.set_compact(self._current_path)

    def _on_error(self, msg: str) -> None:
        self.status_label.setText(f"Ошибка: {msg}")
        self.toasts.show(f"Ошибка: {msg}", "error")

        QMessageBox.critical(self, "Ошибка анализа", msg)
        self.analysis_failed.emit(msg)

    # =========================================================================
    # HANDLERS — детали (модалки)
    # =========================================================================

    def _on_contra_details(self, contra: dict) -> None:
        ContradictionDialog(contra, parent=self).exec()

    # >>> МЕСТО ДЛЯ ДРУГИХ МОДАЛОК <<<
    def _on_finding_details(self, finding: dict) -> None:
        FindingDialog(finding, parent=self).exec()
    # Шаг 7:  def _on_finding_details(self, finding: dict) -> None:
    #             FindingDialog(finding, parent=self).exec()
    # >>> /ДРУГИЕ МОДАЛКИ <<<

    # =========================================================================
    # HANDLERS — управление состоянием
    # =========================================================================

    def _on_thread_done(self) -> None:
        self._set_busy(False)
        self._worker = None

    def _set_busy(self, busy: bool) -> None:
        # Блокируем drop zone на время прогона — исключаем второй анализ.
        self.drop_zone.setEnabled(not busy)

        # >>> ПОКАЗАТЬ/СКРЫТЬ ПРОГРЕСС <<<
        self.progress.setVisible(busy)
        # self.progress.setVisible(busy)
        # >>> /ПРОГРЕСС <<<

    def _reset_results(self) -> None:
        """Сброс всего, что показывает результаты прошлого прогона."""
        self.summary.clear()
        self.contradictions.clear()

        # >>> СБРОС ДРУГИХ СЕКЦИЙ <<<
        self.findings.clear()
        # Шаг 7:  self.findings.clear()
        # >>> /СБРОС ДРУГИХ СЕКЦИЙ <<<

    # =========================================================================
    # API ДЛЯ МЕНЮ
    # =========================================================================

    def reanalyze(self) -> None:
        """F5 из главного меню — повторный прогон того же файла."""
        if not self._current_path:
            return
        if self._worker and self._worker.isRunning():
            return
        self._reset_results()
        self._run_analysis()

    def open_file_dialog(self) -> None:
        """Ctrl+O из главного меню — открыть QFileDialog на drop zone."""
        self.drop_zone.open_dialog()

    # >>> ДРУГИЕ МЕТОДЫ ДЛЯ МЕНЮ <<<
    # Например, экспорт отчёта, если будет в меню «Файл → Экспорт».
    # def export_json(self) -> None: ...
    # >>> /ДРУГИЕ МЕТОДЫ ДЛЯ МЕНЮ <<<