"""Multi-pcap GUI: worker + RunView с поддержкой list[Path]."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKER = REPO_ROOT / "paradox_gui" / "workers" / "analysis_worker.py"
RUN_VIEW = REPO_ROOT / "paradox_gui" / "views" / "run_view.py"


def _patch(path, old, new, name):
    src = path.read_text(encoding="utf-8")
    if new in src and old not in src:
        print(f"[SKIP] {name}: already applied")
        return True
    if old not in src:
        print(f"[ERROR] {name}: anchor not found in {path.name}", file=sys.stderr)
        return False
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


# ============================================================
# 1. AnalysisWorker: принимать str | list[str]
# ============================================================
def patch_worker():
    old = (
        '    def __init__(\n'
        '            self,\n'
        '            pcap_path: str,\n'
        '            config,\n'
        '            disabled_detectors: set[str] | None = None,\n'
        '            disabled_contradictions: set[str] | None = None,\n'
        '            parent=None,\n'
        '    ) -> None:\n'
        '        super().__init__(parent)\n'
        '        self._pcap_path = Path(pcap_path)\n'
        '        self._config = config\n'
        '        self._disabled_detectors = disabled_detectors or set()\n'
        '        self._disabled_contradictions = disabled_contradictions or set()\n'
    )
    new = (
        '    def __init__(\n'
        '            self,\n'
        '            pcap_path: str | list[str],\n'
        '            config,\n'
        '            disabled_detectors: set[str] | None = None,\n'
        '            disabled_contradictions: set[str] | None = None,\n'
        '            parent=None,\n'
        '    ) -> None:\n'
        '        super().__init__(parent)\n'
        '        # v1.2: multi-pcap — принимаем один путь или список\n'
        '        if isinstance(pcap_path, list):\n'
        '            self._pcap_paths = [Path(p) for p in pcap_path]\n'
        '            self._is_multi = True\n'
        '            self._pcap_path = self._pcap_paths[0]  # для совместимости\n'
        '        else:\n'
        '            self._pcap_paths = [Path(pcap_path)]\n'
        '            self._is_multi = False\n'
        '            self._pcap_path = self._pcap_paths[0]\n'
        '        self._config = config\n'
        '        self._disabled_detectors = disabled_detectors or set()\n'
        '        self._disabled_contradictions = disabled_contradictions or set()\n'
    )
    return _patch(WORKER, old, new, "worker: init accepts list")


def patch_worker_run():
    old = (
        '            from paradox.pipeline import (\n'
        '                PipelineCancelled,\n'
        '                run_pipeline,\n'
        '            )\n'
    )
    new = (
        '            from paradox.pipeline import (\n'
        '                PipelineCancelled,\n'
        '                run_multi_pipeline,\n'
        '                run_pipeline,\n'
        '            )\n'
    )
    if not _patch(WORKER, old, new, "worker: import run_multi_pipeline"):
        return False

    old_call = (
        '        t0 = time.perf_counter()\n'
        '        try:\n'
        '            report = run_pipeline(\n'
        '                self._pcap_path,\n'
        '                self._config,\n'
        '                should_stop=self.isInterruptionRequested,\n'
        '                on_progress=self._emit_progress,\n'
        '                on_phase=self._emit_phase,\n'
        '            )\n'
    )
    new_call = (
        '        t0 = time.perf_counter()\n'
        '        try:\n'
        '            if self._is_multi:\n'
        '                report = run_multi_pipeline(\n'
        '                    self._pcap_paths,\n'
        '                    self._config,\n'
        '                    should_stop=self.isInterruptionRequested,\n'
        '                    on_progress=self._emit_progress,\n'
        '                    on_phase=self._emit_phase,\n'
        '                )\n'
        '            else:\n'
        '                report = run_pipeline(\n'
        '                    self._pcap_path,\n'
        '                    self._config,\n'
        '                    should_stop=self.isInterruptionRequested,\n'
        '                    on_progress=self._emit_progress,\n'
        '                    on_phase=self._emit_phase,\n'
        '                )\n'
    )
    if not _patch(WORKER, old_call, new_call, "worker: call multi vs single"):
        return False

    # size_bytes и duration_sec: для multi суммируем размеры
    old_size = (
        '        summary = dict(report.get("summary", {}))\n'
        '        summary.setdefault("size_bytes", self._pcap_path.stat().st_size)\n'
        '        summary.setdefault("duration_sec", elapsed)\n'
        '        report["summary"] = summary\n'
    )
    new_size = (
        '        summary = dict(report.get("summary", {}))\n'
        '        if "size_bytes" not in summary:\n'
        '            total_size = 0\n'
        '            for p in self._pcap_paths:\n'
        '                try:\n'
        '                    total_size += p.stat().st_size\n'
        '                except OSError:\n'
        '                    pass\n'
        '            summary["size_bytes"] = total_size\n'
        '        summary.setdefault("duration_sec", elapsed)\n'
        '        report["summary"] = summary\n'
    )
    return _patch(WORKER, old_size, new_size, "worker: sum size_bytes")


# ============================================================
# 2. RunView: state + кнопка
# ============================================================
def patch_run_view_imports():
    old = (
        'from PySide6.QtCore import Signal\n'
        'from PySide6.QtWidgets import (\n'
        '    QDialog,\n'
        '    QScrollArea,\n'
    )
    new = (
        'from PySide6.QtCore import Signal\n'
        'from PySide6.QtWidgets import (\n'
        '    QDialog,\n'
        '    QFileDialog,\n'
        '    QScrollArea,\n'
    )
    return _patch(RUN_VIEW, old, new, "run_view: import QFileDialog")


def patch_run_view_state():
    old = (
        '        self._worker: AnalysisWorker | None = None\n'
        '        self._current_path: str | None = None\n'
    )
    new = (
        '        self._worker: AnalysisWorker | None = None\n'
        '        self._current_path: str | None = None\n'
        '        # v1.2: multi-pcap\n'
        '        self._current_paths: list[str] = []\n'
    )
    return _patch(RUN_VIEW, old, new, "run_view: _current_paths state")


def patch_run_view_button():
    old = (
        '        # --- Drop zone ---\n'
        '        self.drop_zone = DropZone()\n'
        '        self.drop_zone.pcap_selected.connect(self._on_pcap_selected)\n'
        '        layout.addWidget(self.drop_zone)\n'
    )
    new = (
        '        # --- Drop zone ---\n'
        '        self.drop_zone = DropZone()\n'
        '        self.drop_zone.pcap_selected.connect(self._on_pcap_selected)\n'
        '        layout.addWidget(self.drop_zone)\n'
        '\n'
        '        # Кнопка "Открыть несколько pcap" (v1.2 multi-pcap)\n'
        '        from PySide6.QtWidgets import QPushButton as _QBtn, QHBoxLayout as _QH\n'
        '        multi_row = _QH()\n'
        '        multi_row.setContentsMargins(0, 0, 0, 0)\n'
        '        self.btn_multi_pcap = _QBtn("Открыть несколько pcap для слияния…")\n'
        '        self.btn_multi_pcap.setToolTip(\n'
        '            "Выбрать 2+ pcap файла — они будут склеены в один датасет.\\n"\n'
        '            "Beaconing, DGA и slow-scan детекторы увидят длинный горизонт."\n'
        '        )\n'
        '        self.btn_multi_pcap.clicked.connect(self._on_multi_pcap_clicked)\n'
        '        multi_row.addWidget(self.btn_multi_pcap)\n'
        '        multi_row.addStretch(1)\n'
        '        layout.addLayout(multi_row)\n'
    )
    return _patch(RUN_VIEW, old, new, "run_view: multi-pcap button")


def patch_run_view_handlers():
    # Обработчики + адаптация _run_analysis
    old = (
        '    def _on_pcap_selected(self, path: str) -> None:\n'
        '        if self._worker and self._worker.isRunning():\n'
        '            return\n'
        '        self._current_path = path\n'
        '        self._reset_results()\n'
        '        self._run_analysis()\n'
    )
    new = (
        '    def _on_pcap_selected(self, path: str) -> None:\n'
        '        if self._worker and self._worker.isRunning():\n'
        '            return\n'
        '        self._current_path = path\n'
        '        self._current_paths = [path]\n'
        '        self._reset_results()\n'
        '        self._run_analysis()\n'
        '\n'
        '    def _on_multi_pcap_clicked(self) -> None:\n'
        '        if self._worker and self._worker.isRunning():\n'
        '            return\n'
        '        paths, _ = QFileDialog.getOpenFileNames(\n'
        '            self,\n'
        '            "Выбрать pcap-файлы для слияния (2+)",\n'
        '            "",\n'
        '            "Packet captures (*.pcap *.pcapng *.cap);;Все файлы (*)",\n'
        '        )\n'
        '        if not paths:\n'
        '            return\n'
        '        if len(paths) < 2:\n'
        '            from PySide6.QtWidgets import QMessageBox\n'
        '            QMessageBox.information(\n'
        '                self, "Нужно 2+ файла",\n'
        '                "Выбран 1 файл. Для одиночного анализа — перетащите его в зону выше.",\n'
        '            )\n'
        '            return\n'
        '        self._current_paths = list(paths)\n'
        '        self._current_path = paths[0]\n'
        '        self._reset_results()\n'
        '        self._run_analysis()\n'
    )
    return _patch(RUN_VIEW, old, new, "run_view: multi handlers")


def patch_run_analysis():
    old = (
        '        self._worker = AnalysisWorker(\n'
        '            self._current_path, config,\n'
        '            disabled_detectors=self._disabled_detectors,\n'
        '            disabled_contradictions=self._disabled_contradictions,\n'
        '        )\n'
    )
    new = (
        '        # v1.2: если путей > 1 — multi-pcap режим\n'
        '        _paths_or_path = (\n'
        '            list(self._current_paths) if len(self._current_paths) > 1\n'
        '            else self._current_path\n'
        '        )\n'
        '        self._worker = AnalysisWorker(\n'
        '            _paths_or_path, config,\n'
        '            disabled_detectors=self._disabled_detectors,\n'
        '            disabled_contradictions=self._disabled_contradictions,\n'
        '        )\n'
    )
    return _patch(RUN_VIEW, old, new, "run_view: worker call")


def patch_on_ok_compact():
    # В _on_ok компактный drop_zone: если multi — пишем "N файлов"
    old = (
        '        # Компактный drop zone после успешного прогона.\n'
        '        if self._current_path:\n'
        '            self.drop_zone.set_compact(self._current_path)\n'
    )
    new = (
        '        # Компактный drop zone после успешного прогона.\n'
        '        if len(self._current_paths) > 1:\n'
        '            self.drop_zone.set_compact(f"[multi] {len(self._current_paths)} файлов")\n'
        '        elif self._current_path:\n'
        '            self.drop_zone.set_compact(self._current_path)\n'
    )
    return _patch(RUN_VIEW, old, new, "run_view: on_ok compact")


def main():
    print("=" * 60)
    print(" multi-pcap: gui")
    print("=" * 60)
    ok = True
    for fn in (
        patch_worker,
        patch_worker_run,
        patch_run_view_imports,
        patch_run_view_state,
        patch_run_view_button,
        patch_run_view_handlers,
        patch_run_analysis,
        patch_on_ok_compact,
    ):
        try:
            if not fn(): ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
