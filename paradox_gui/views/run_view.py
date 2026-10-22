"""Вкладка «Прогон».

Цепочка: drop zone → QThread(worker) → run_pipeline → report →
summary grid + секция противоречий + таблица findings.
"""
import time
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from paradox.analyzers.counterfactual import evaluate_what_if
from paradox_gui.dialogs.carved_files_dialog import CarvedFilesDialog
from paradox_gui.dialogs.contradiction_dialog import ContradictionDialog
from paradox_gui.dialogs.finding_dialog import FindingDialog
from paradox_gui.dialogs.graph_dialog import GraphDialog
from paradox_gui.dialogs.what_if_dialog import WhatIfDialog
from paradox_gui.i18n import tr
from paradox_gui.widgets.absence_panel import AbsencePanel
from paradox_gui.widgets.contradictions_section import ContradictionsSection
from paradox_gui.widgets.drop_zone import DropZone
from paradox_gui.widgets.findings_table import FindingsTable
from paradox_gui.widgets.summary_grid import SummaryGrid
from paradox_gui.widgets.toast import ToastManager
from paradox_gui.workers.analysis_worker import AnalysisWorker

from ..widgets.highlights_panel import HighlightsPanel
from ..widgets.observations_panel import ObservationsPanel


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

    def __init__(self, parent=None, store=None) -> None:
        super().__init__(parent)
        self._store = store
        # >>> СОСТОЯНИЕ <<<
        self._worker: AnalysisWorker | None = None
        self._current_path: str | None = None
        # v1.2: multi-pcap
        self._current_paths: list[str] = []
        self._last_report: dict | None = None
        self._config_overrides: dict = {}
        self._disabled_detectors: set[str] = set()
        self._disabled_contradictions: set[str] = set()
        # >>> ОСТАНОВКА <<<
        # True — пользователь нажал «Остановить» или Esc. Сбрасывается
        # в _on_ok / _on_error / _on_thread_done.
        self._stop_requested: bool = False
        self._analysis_t0: float = 0.0
        # >>> /ОСТАНОВКА <<<
        # >>> /СОСТОЯНИЕ <<<
        self._build_ui()
        self.toasts = ToastManager(self)
        self._load_from_store()

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

        # Кнопка "Открыть несколько pcap" (v1.2 multi-pcap)
        from PySide6.QtWidgets import QHBoxLayout as _QH
        from PySide6.QtWidgets import QPushButton as _QBtn
        multi_row = _QH()
        multi_row.setContentsMargins(0, 0, 0, 0)
        self.btn_multi_pcap = _QBtn(tr("run.multi_pcap"))
        self.btn_multi_pcap.setToolTip(
            "Выбрать 2+ pcap файла — они будут склеены в один датасет.\n"
            "Beaconing, DGA и slow-scan детекторы увидят длинный горизонт."
        )
        self.btn_multi_pcap.clicked.connect(self._on_multi_pcap_clicked)
        multi_row.addWidget(self.btn_multi_pcap)
        multi_row.addStretch(1)
        layout.addLayout(multi_row)

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
        self.stop_btn = QPushButton(tr("run.stop"))
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

        self.absence = AbsencePanel()
        layout.addWidget(self.absence)
        self.highlights = HighlightsPanel()
        layout.addWidget(self.highlights)


        # --- Противоречия ---
        self.contradictions = ContradictionsSection()
        self.contradictions.details_requested.connect(self._on_contra_details)
        layout.addWidget(self.contradictions)

        # --- Findings ---
        findings_header = QHBoxLayout()
        lbl_findings = QLabel(tr("run.findings"))
        lbl_findings.setObjectName("h1")
        findings_header.addWidget(lbl_findings)
        findings_header.addStretch(1)

        self.btn_graph = QPushButton(tr("run.graph"))
        self.btn_graph.setEnabled(False)
        self.btn_graph.clicked.connect(self._on_graph_clicked)
        findings_header.addWidget(self.btn_graph)

        self.btn_attack_graph = QPushButton(tr("run.attack_graph"))
        self.btn_attack_graph.setEnabled(False)
        self.btn_attack_graph.clicked.connect(self._on_attack_graph_clicked)
        findings_header.addWidget(self.btn_attack_graph)

        self.btn_carved = QPushButton(tr("run.files"))
        self.btn_carved.setEnabled(False)
        self.btn_carved.clicked.connect(self._on_carved_clicked)
        findings_header.addWidget(self.btn_carved)

        self.btn_what_if = QPushButton(tr("run.what_if"))
        self.btn_what_if.setEnabled(False)
        self.btn_what_if.clicked.connect(self._on_what_if_clicked)

        self.btn_reset_filter = QPushButton(tr("run.reset_filter"))
        self.btn_reset_filter.setVisible(False)
        self.btn_reset_filter.clicked.connect(self._on_reset_what_if)

        findings_header.addWidget(self.btn_what_if)
        findings_header.addWidget(self.btn_reset_filter)
        layout.addLayout(findings_header)

        self.findings = FindingsTable()
        self.findings.row_activated.connect(self._on_finding_details)
        self.findings.host_story_requested.connect(self._on_host_story_requested)
        layout.addWidget(self.findings, stretch=1)

        # --- Статус-строка внизу ---
        self.status_label = QLabel(tr("run.no_file"))
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)

    # =========================================================================
    # HANDLERS — запуск прогона
    # =========================================================================

    def _on_pcap_selected(self, path: str) -> None:
        if self._worker and self._worker.isRunning():
            return
        self._current_path = path
        self._current_paths = [path]
        self._reset_results()
        self._run_analysis()

    def _on_multi_pcap_clicked(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Выбрать pcap-файлы для слияния (2+)",
            "",
            "Packet captures (*.pcap *.pcapng *.cap);;Все файлы (*)",
        )
        if not paths:
            return
        if len(paths) < 2:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(
                self, tr("run.multi_warning_title"),
                tr("run.multi_warning_body"),
            )
            return

        # Защита от суммарно больших multi-pcap.
        total_mb = 0.0
        try:
            for p in paths:
                total_mb += Path(p).stat().st_size / (1024 * 1024)
        except OSError:
            pass
        _LIMIT = 500
        if total_mb > _LIMIT:
            answer = QMessageBox.question(
                self,
                tr("run.large_pcap_title"),
                tr("run.large_multi_pcap_body",
                   count=len(paths), size=total_mb, limit=_LIMIT),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self._current_paths = list(paths)
        self._current_path = paths[0]
        self._reset_results()
        self._run_analysis()

    def _run_analysis(self) -> None:
        if not self._current_path:
            return
        try:
            from paradox_gui.config_builder import (
                build_config_with_overrides,
            )
            config = build_config_with_overrides(self._config_overrides)
        except ImportError as e:
            self._on_error(f"Не удалось импортировать Config: {e}")
            return
        except (ValueError, OSError) as e:
            self._on_error(f"Некорректные настройки: {e}")
            return

        self._set_busy(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self._analysis_t0 = time.monotonic()
        self.status_label.setText("Извлечение · 0%")

        # v1.2: если путей > 1 — multi-pcap режим
        _paths_or_path = (
            list(self._current_paths) if len(self._current_paths) > 1
            else self._current_path
        )
        self._worker = AnalysisWorker(
            _paths_or_path, config,
            disabled_detectors=self._disabled_detectors,
            disabled_contradictions=self._disabled_contradictions,
        )
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.error.connect(self._on_error)
        self._worker.cancelled.connect(self._on_cancelled)
        self._worker.progress.connect(self._on_progress)
        self._worker.phase.connect(self._on_phase)
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
        if hasattr(self, 'absence'):
            self.absence.update_report(report)
        if hasattr(self, 'highlights'):
            self.highlights.update_report(report)
        self.contradictions.set_contradictions(report.get("contradictions", []))
        self._original_findings = report.get("findings", []).copy()
        self.findings.set_findings(self._original_findings)
        self.btn_what_if.setEnabled(True)
        self.btn_graph.setEnabled(True)
        _ag = report.get('attack_graph') or {}
        # v1.2.1: включаем если есть ЛЮБЫЕ данные графа (не только paths).
        _has_attack_data = bool(_ag.get('nodes') or _ag.get('paths'))
        self.btn_attack_graph.setEnabled(_has_attack_data)
        self.btn_carved.setEnabled(bool((report.get('carved_files') or {}).get('total')))
        self.btn_reset_filter.setVisible(False)

        self.status_label.setText(tr(
            "run.done",
            findings=s.get('findings', 0),
            contradictions=s.get('contradictions', 0),
            duration=s.get('duration_sec', 0),
        ))
        self.toasts.show(
            f"Готово: {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий",
            "success",
        )
        self.analysis_finished.emit(report)

        # Компактный drop zone после успешного прогона.
        if len(self._current_paths) > 1:
            self.drop_zone.set_compact(
                "",
                display_name=f"[multi] {len(self._current_paths)} файлов",
            )
        elif self._current_path:
            self.drop_zone.set_compact(self._current_path)

    def load_report(self, report: dict) -> None:
        """Заполнить RunView отчётом из внешнего источника (JSON).

        Отличие от _on_ok: не эмитит analysis_finished. Это
        критично — иначе MainWindow._on_analysis_finished
        получит сигнал и добавит в Историю дубликат записи,
        которую сам же уже добавил при открытии файла.
        """
        self._stop_requested = False
        self._last_report = report
        s = report.get("summary", {}) or {}
        self.summary.set_values(s)
        if hasattr(self, "observations"):
            self.observations.update_report(report)
        if hasattr(self, "absence"):
            self.absence.update_report(report)
        if hasattr(self, "highlights"):
            self.highlights.update_report(report)
        self.contradictions.set_contradictions(
            report.get("contradictions", [])
        )
        self._original_findings = report.get("findings", []).copy()
        self.findings.set_findings(self._original_findings)
        self.btn_what_if.setEnabled(True)
        self.btn_graph.setEnabled(True)
        _ag = report.get('attack_graph') or {}
        self.btn_attack_graph.setEnabled(
            bool(_ag.get('nodes') or _ag.get('paths'))
        )
        self.btn_carved.setEnabled(bool((report.get('carved_files') or {}).get('total')))
        self.btn_reset_filter.setVisible(False)
        self.status_label.setText(tr(
            "run.loaded",
            findings=s.get('findings', 0),
            contradictions=s.get('contradictions', 0),
        ))
        self._set_busy(False)

    def _on_error(self, msg: str) -> None:
        self._stop_requested = False
        self.status_label.setText(tr("run.error", msg=msg))
        self.toasts.show(f"Ошибка: {msg}", "error")
        QMessageBox.critical(self, "Ошибка анализа", msg)
        self.analysis_failed.emit(msg)

    # =========================================================================
    # HANDLERS — детали (модалки)
    # =========================================================================

    # Доли фаз на общем баре 0..100. Extract — 90% времени,
    # поэтому он единственная "длинная" полоса, остальные — тонкие.
    _PHASE_RANGES = {
        "extract":        (0,  90),
        "detect":         (90, 95),
        "contradictions": (95, 98),
        "report":         (98, 100),
    }

    def _map_phase(self, name: str, done: int, total: int) -> int:
        lo, hi = self._PHASE_RANGES.get(name, (0, 100))
        if total <= 0:
            return hi
        frac = min(1.0, done / total)
        return int(lo + (hi - lo) * frac)

    def _on_progress(self, bytes_read: int, total: int) -> None:
        """Фаза extract: 0..90% + скорость + ETA."""
        if total <= 0:
            return
        pct = self._map_phase("extract", bytes_read, total)
        self.progress.setValue(pct)

        elapsed = time.monotonic() - self._analysis_t0
        if elapsed >= 1.0 and bytes_read > 0:
            speed_mbs = (bytes_read / elapsed) / (1024 * 1024)
            remaining = max(0.0, (total - bytes_read) / (bytes_read / elapsed))
            self.status_label.setText(
                tr("run.extracting_speed", pct=pct, speed=speed_mbs, remaining=remaining)
            )
        else:
            self.status_label.setText(tr("run.extracting", pct=pct))

    def _on_phase(self, name: str, done: int, total: int,
                  detail: str = "") -> None:
        """Coarse phases after extract.

        detail для detect — имя текущего детектора.
        """
        pct = self._map_phase(name, done, total)
        self.progress.setValue(pct)
        if name == "detect":
            if detail:
                self.status_label.setText(tr("run.detecting_detail", done=done, total=total, detail=detail))
            else:
                self.status_label.setText(tr("run.detecting", done=done, total=total))
        elif name == "contradictions":
            self.status_label.setText(tr("run.contradictions"))
        elif name == "report":
            self.status_label.setText(tr("run.reports"))

    def _on_cancelled(self) -> None:
        """Пользователь остановил прогон. Не ошибка."""
        self._stop_requested = False
        self.status_label.setText(tr("run.cancelled"))
        self.analysis_cancelled.emit()

    def _on_contra_details(self, contra: dict) -> None:
        ContradictionDialog(contra, parent=self).exec()

    def _on_carved_clicked(self) -> None:
        if not self._last_report:
            return
        CarvedFilesDialog(self._last_report, self).exec()

    def _on_graph_clicked(self) -> None:
        if not self._last_report:
            return
        GraphDialog(self._last_report, self).exec()

    def _on_attack_graph_clicked(self) -> None:
        if not self._last_report:
            return
        from paradox_gui.dialogs.attack_graph_dialog import AttackGraphDialog
        AttackGraphDialog(self._last_report, self).exec()

    def _on_what_if_clicked(self) -> None:
        if not self._last_report:
            return

        dialog = WhatIfDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        exclude_ips, exclude_domains = dialog.get_exclusions()
        if not exclude_ips and not exclude_domains:
            return

        res = evaluate_what_if(
            self._last_report,
            exclude_ips=exclude_ips,
            exclude_domains=exclude_domains
        )

        remaining = res["remaining_findings"]
        removed_count = res["removed_count"]

        self.findings.set_findings(remaining)
        self.btn_reset_filter.setVisible(True)

        self.toasts.show(
            f"What-If: удалено {removed_count} находок",
            "info"
        )
        self.status_label.setText(
            f"What-If активно · осталось {len(remaining)} findings"
        )

    def _on_reset_what_if(self) -> None:
        self.findings.set_findings(self._original_findings)
        self.btn_reset_filter.setVisible(False)
        self.status_label.setText(
            f"Фильтр сброшен · {len(self._original_findings)} findings"
        )

    def _on_host_story_requested(self, ip: str) -> None:
        if not self._last_report:
            return

        from paradox.analyzers.story import build_host_story
        from paradox_gui.dialogs.host_story_dialog import HostStoryDialog

        story = build_host_story(self._last_report, ip)
        dialog = HostStoryDialog(ip, story, self)
        dialog.exec()

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
        self._original_findings = []
        if hasattr(self, "btn_carved"):
            self.btn_carved.setEnabled(False)
            self.btn_carved.setText("Файлы")
        if hasattr(self, "btn_what_if"):
            self.btn_what_if.setEnabled(False)
            self.btn_graph.setEnabled(False)
            self.btn_attack_graph.setEnabled(False)
            self.btn_reset_filter.setVisible(False)

    # =========================================================================
    # ОСТАНОВКА
    # =========================================================================

    def stop_analysis(self) -> None:
        """Кооперативная остановка текущего прогона."""
        if not (self._worker and self._worker.isRunning()):
            return
        self._stop_requested = True
        self.status_label.setText("Останавливаю…")
        self.stop_btn.setEnabled(False)
        self._worker.stop()

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

    def _load_from_store(self) -> None:
        """Прочитать сохранённые настройки при старте GUI."""
        if self._store is None:
            return
        data = self._store.load()
        ov = data.get("overrides", {})
        if isinstance(ov, dict) and ov:
            try:
                from paradox.config import Config
                from paradox_gui.settings_rehydrate import (
                    rehydrate_overrides,
                )
                ov = rehydrate_overrides(ov, Config())
            except ImportError:
                pass
            self._config_overrides.update(ov)

        dd = data.get("disabled_detectors", [])
        if isinstance(dd, (list, tuple, set, frozenset)):
            self._disabled_detectors = set(dd)

        dc = data.get("disabled_contradictions", [])
        if isinstance(dc, (list, tuple, set, frozenset)):
            self._disabled_contradictions = set(dc)

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
