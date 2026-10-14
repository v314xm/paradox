"""Вкладка «Прогон».

Цепочка: drop zone → QThread(worker) → run_pipeline → report →
summary grid + секция противоречий + таблица findings.
"""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QScrollArea,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
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
from ..widgets.observations_panel import ObservationsPanel
from ..widgets.highlights_panel import HighlightsPanel


class RunView(QWidget):
    analysis_started = Signal(str)
    analysis_finished = Signal(object)
    analysis_failed = Signal(str)
    # >>> ОСТАНОВКА <<<
    # Отдельный сигнал от analysis_failed: «остановил пользователь» —
    # не ошибка, и в статус-баре окна должно быть «Остановлено», а не
    # «Ошибка». MainWindow слушает оба.
    analysis_cancelled = Signal()
    # >>> /ОСТАНОВКА <<<

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # >>> СОСТОЯНИЕ <<<
        self._worker: AnalysisWorker | None = None
        self._current_path: str | None = None
        self._last_report: dict | None = None
        self._config_overrides: dict = {}
        self._disabled_detectors: set[str] = set()
        self._disabled_contradictions: set[str] = set()
        # >>> ОСТАНОВКА <<<
        # True — пользователь нажал «Остановить» или Esc. Сбрасывается
        # в _on_ok / _on_error / _on_thread_done.
        self._stop_requested: bool = False
        # >>> /ОСТАНОВКА <<<
        # >>> /СОСТОЯНИЕ <<<
        self._build_ui()
        self.toasts = ToastManager(self)

    # =========================================================================
    # UI
    # =========================================================================

    def _build_ui(self) -> None:
        # AUTO-INSERTED-SCROLL
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        scroll.setWidget(inner)
        outer.addWidget(scroll)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # --- Drop zone ---
        self.drop_zone = DropZone()
        self.drop_zone.pcap_selected.connect(self._on_pcap_selected)
        layout.addWidget(self.drop_zone)

        # --- Progress bar + кнопка «Остановить» ---
        # Indeterminate: точный процент требует правки ядра.
        # Кнопка в одном ряду с прогрессом — иначе она прыгает по layout
        # при показе/скрытии и дёргает соседние виджеты.
        progress_row = QHBoxLayout()
        progress_row.setContentsMargins(0, 0, 0, 0)
        progress_row.setSpacing(8)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        progress_row.addWidget(self.progress, stretch=1)

        # >>> ОСТАНОВКА <<<
        self.stop_btn = QPushButton("Остановить")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setVisible(False)
        self.stop_btn.clicked.connect(self.stop_analysis)
        progress_row.addWidget(self.stop_btn)
        # >>> /ОСТАНОВКА <<<

        layout.addLayout(progress_row)

        # --- Summary grid ---
        self.summary = SummaryGrid()
        layout.addWidget(self.summary)
        self.observations = ObservationsPanel()
        layout.addWidget(self.observations)
        self.highlights = HighlightsPanel()
        layout.addWidget(self.highlights)


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
        self._stop_requested = False
        self._last_report = report
        s = report.get("summary", {})
        self.summary.set_values(s)
        # AUTO-INSERTED-UPDATE-CALL
        if hasattr(self, 'observations'):
            self.observations.update_report(report)
        if hasattr(self, 'highlights'):
            self.highlights.update_report(report)
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
        self._stop_requested = False
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

        # Ждём, пока QThread реально завершится. Сигнал finished
        # приходит РАНЬШЕ, чем C++-объект отпустит ресурсы. Без
        # wait() можно потерять ссылку на ещё живой QThread, и
        # следующий сборщик мусора уронит процесс без traceback.
        w = self._worker
        if w is not None:
            # 2000 мс — с запасом. На практике поток к моменту
            # сигнала finished почти всегда уже мёртв, возврат
            # мгновенный. Если бы ждали долго — тут был бы UI-фриз,
            # но этого не происходит.
            w.wait(2000)
        self._worker = None

        # Сбрасываем накопленный мусор от прогона. На больших pcap
        # это десятки тысяч мелких объектов. Без ручного вызова
        # gen-2 может сработать в неудобный момент — во время старта
        # следующего прогона, что даёт рывок памяти и CPU.
        import gc
        gc.collect()

    def _set_busy(self, busy: bool) -> None:
        self.drop_zone.setEnabled(not busy)
        self.progress.setVisible(busy)
        # >>> ОСТАНОВКА <<<
        self.stop_btn.setVisible(busy)
        self.stop_btn.setEnabled(busy)
        # >>> /ОСТАНОВКА <<<

    def _reset_results(self) -> None:
        self.summary.clear()
        self.contradictions.clear()
        self.findings.clear()
        self._last_report = None

    # =========================================================================
    # ОСТАНОВКА
    # =========================================================================

    def stop_analysis(self) -> None:
        """Временно отключено: QThread.terminate() валит процесс.

        Вернёмся к реализации через detach воркера отдельным шагом.
        Пока метод — no-op: Esc и кнопка не делают ничего,
        окно не падает.
        """
        return

    def is_busy(self) -> bool:
        """True — идёт анализ. Нужно MainWindow для Esc-хендлера."""
        return bool(self._worker and self._worker.isRunning())

    # =========================================================================
    # API ДЛЯ МЕНЮ
    # =========================================================================

    def set_config_overrides(self, overrides: dict) -> None:
        """Переопределения Config из вкладки «Настройки».

        Мердж, а не замена: каждая секция настроек шлёт только свои
        ключи. Если Пороги применили {a: 1}, а Brute force — {b: 2},
        в overrides должно оказаться {a: 1, b: 2}.
        """
        self._config_overrides.update(overrides)

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
