"""Вкладка «Прогон».

Цепочка: drop zone → QThread(worker) → run_pipeline → report →
summary grid + секция противоречий + таблица findings.
"""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QLabel,
    QMessageBox,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from pcap_triage_gui.dialogs.contradiction_dialog import ContradictionDialog
from pcap_triage_gui.dialogs.finding_dialog import FindingDialog
from pcap_triage_gui.widgets.contradictions_section import ContradictionsSection
from pcap_triage_gui.widgets.drop_zone import DropZone
from pcap_triage_gui.widgets.findings_table import FindingsTable
from pcap_triage_gui.widgets.summary_grid import SummaryGrid
from pcap_triage_gui.widgets.toast import ToastManager
from pcap_triage_gui.workers.analysis_worker import AnalysisWorker


class RunView(QWidget):
    analysis_started = Signal(str)
    analysis_finished = Signal(object)
    analysis_failed = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # >>> СОСТОЯНИЕ <<<
        self._worker: AnalysisWorker | None = None
        self._current_path: str | None = None
        self._last_report: dict | None = None
        self._config_overrides: dict = {}
        self._disabled_detectors: set[str] = set()
        self._disabled_contradictions: set[str] = set()
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

        # --- Progress bar ---
        # Indeterminate: точный процент требует правки ядра.
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # --- Summary grid ---
        self.summary = SummaryGrid()
        layout.addWidget(self.summary)

        # --- Противоречия ---
        self.contradictions = ContradictionsSection()
        self.contradictions.details_requested.connect(self._on_contra_details)
        layout.addWidget(self.contradictions)

        # --- Findings ---
        self.findings = FindingsTable()
        self.findings.row_activated.connect(self._on_finding_details)
        layout.addWidget(self.findings, stretch=1)

        # --- Статус-строка внизу ---
        self.status_label = QLabel("Файл не выбран.")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)

    # =========================================================================
    # HANDLERS — запуск прогона
    # =========================================================================

    def _on_pcap_selected(self, path: str) -> None:
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
            # Переопределения из вкладки «Настройки». Config — frozen
            # dataclass, обычный setattr упадёт. object.__setattr__
            # обходит frozen-защиту точечно.
            for k, v in self._config_overrides.items():
                if hasattr(config, k):
                    object.__setattr__(config, k, v)
        except ImportError as e:
            self._on_error(f"Не удалось импортировать Config: {e}")
            return

        self._set_busy(True)
        self.status_label.setText(f"Анализ: {self._current_path}")

        self._worker = AnalysisWorker(
            self._current_path, config,
            disabled_detectors=self._disabled_detectors,
            disabled_contradictions=self._disabled_contradictions,
        )
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_thread_done)
        self._worker.start()
        self.analysis_started.emit(self._current_path)

    # =========================================================================
    # HANDLERS — результаты прогона
    # =========================================================================

    def _on_ok(self, report: dict) -> None:
        self._last_report = report
        s = report.get("summary", {})
        self.summary.set_values(s)
        self.contradictions.set_contradictions(report.get("contradictions", []))
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

        # Компактный drop zone после успешного прогона.
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

    def _on_finding_details(self, finding: dict) -> None:
        FindingDialog(finding, parent=self).exec()

    # =========================================================================
    # HANDLERS — управление состоянием
    # =========================================================================

    def _on_thread_done(self) -> None:
        self._set_busy(False)
        self._worker = None

    def _set_busy(self, busy: bool) -> None:
        self.drop_zone.setEnabled(not busy)
        self.progress.setVisible(busy)

    def _reset_results(self) -> None:
        self.summary.clear()
        self.contradictions.clear()
        self.findings.clear()
        self._last_report = None

    # =========================================================================
    # API ДЛЯ МЕНЮ
    # =========================================================================

    def set_config_overrides(self, overrides: dict) -> None:
        """Переопределения Config из вкладки «Настройки»."""
        self._config_overrides = dict(overrides)

    def set_disabled_detectors(self, names: set[str]) -> None:
        """Отключённые детекторы из вкладки «Настройки»."""
        self._disabled_detectors = set(names)

    def set_disabled_contradictions(self, names: set[str]) -> None:
        """Отключённые правила ContradictionDetector из вкладки «Настройки».

        Ключи — имена классов (VictimMakesAttackRule, ...).
        """
        self._disabled_contradictions = set(names)

    def reanalyze(self) -> None:
        """F5 из главного меню — повторный прогон того же файла."""
        if not self._current_path:
            return
        if self._worker and self._worker.isRunning():
            return
        self._reset_results()
        self._run_analysis()

    def last_report(self) -> dict | None:
        """Последний успешный report или None. Для экспорта из меню."""
        return self._last_report

    def open_file_dialog(self) -> None:
        """Ctrl+O из главного меню — открыть QFileDialog на drop zone."""
        self.drop_zone.open_dialog()