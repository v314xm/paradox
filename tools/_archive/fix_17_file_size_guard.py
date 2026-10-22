# tools/fix_17_file_size_guard.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "17-file-size-guard"
TITLE = "GUI: защита от больших pcap (>500 МБ) и JSON (>100 МБ)"
REL_DROP = "paradox_gui/widgets/drop_zone.py"
REL_RUN = "paradox_gui/views/run_view.py"
REL_MAIN = "paradox_gui/main_window.py"
REL_RU = "paradox_gui/i18n/_ru.py"
REL_EN = "paradox_gui/i18n/_en.py"

# --- 1. i18n strings ---
_RU_OLD = '''    "run.multi_warning_body": "Выбран 1 файл. Для одиночного анализа — перетащите его в зону выше.",
'''
_RU_NEW = '''    "run.multi_warning_body": "Выбран 1 файл. Для одиночного анализа — перетащите его в зону выше.",
    "run.large_pcap_title": "Большой pcap",
    "run.large_pcap_body": "Файл весит {size:.0f} МБ (порог предупреждения: {limit} МБ).\\nАнализ может занять несколько минут и съесть много RAM. Продолжить?",
    "run.large_multi_pcap_body": "Выбрано {count} файлов, суммарно {size:.0f} МБ (порог: {limit} МБ).\\nАнализ может занять долго. Продолжить?",
    "error.large_json_title": "Большой JSON-отчёт",
    "error.large_json_body": "Файл весит {size:.0f} МБ (порог предупреждения: {limit} МБ).\\nЗагрузка может занять несколько секунд. Продолжить?",
'''
_EN_OLD = '''    "run.multi_warning_body": "1 file selected. For single analysis — drag it into the zone above.",
'''
_EN_NEW = '''    "run.multi_warning_body": "1 file selected. For single analysis — drag it into the zone above.",
    "run.large_pcap_title": "Large pcap",
    "run.large_pcap_body": "File is {size:.0f} MB (warning threshold: {limit} MB).\\nAnalysis may take several minutes and consume a lot of RAM. Continue?",
    "run.large_multi_pcap_body": "{count} files selected, {size:.0f} MB total (threshold: {limit} MB).\\nAnalysis may take a long time. Continue?",
    "error.large_json_title": "Large JSON report",
    "error.large_json_body": "File is {size:.0f} MB (warning threshold: {limit} MB).\\nLoading may take several seconds. Continue?",
'''

# --- 2. DropZone: проверка размера pcap ---
_DROP_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QLabel,
    QVBoxLayout,
)
from paradox_gui.i18n import tr'''
_DROP_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QLabel,
    QMessageBox,
    QVBoxLayout,
)
from paradox_gui.i18n import tr

# Порог предупреждения о размере pcap (в МБ). Ниже порога — без диалога.
_MAX_PCAP_WARN_MB = 500'''

_DROP_EMIT_OLD = '''    def _emit_selected(self, path: str) -> None:
        p = Path(path)
        # Молча выходим, если файл не существует: сообщение об ошибке —
        # дело вызывающей стороны, а не зоны.
        if not p.exists() or not p.is_file():
            return
        self.pcap_selected.emit(str(p.resolve()))
'''
_DROP_EMIT_NEW = '''    def _emit_selected(self, path: str) -> None:
        p = Path(path)
        # Молча выходим, если файл не существует: сообщение об ошибке —
        # дело вызывающей стороны, а не зоны.
        if not p.exists() or not p.is_file():
            return

        # Защита от больших pcap: > 500 МБ — предупредить.
        try:
            size_mb = p.stat().st_size / (1024 * 1024)
        except OSError:
            size_mb = 0
        if size_mb > _MAX_PCAP_WARN_MB:
            answer = QMessageBox.question(
                self,
                tr("run.large_pcap_title"),
                tr("run.large_pcap_body",
                   size=size_mb, limit=_MAX_PCAP_WARN_MB),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.pcap_selected.emit(str(p.resolve()))
'''

# --- 3. RunView: проверка размера при multi-pcap ---
_RUN_MULTI_OLD = '''        if len(paths) < 2:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(
                self, tr("run.multi_warning_title"),
                tr("run.multi_warning_body"),
            )
            return
        self._current_paths = list(paths)
'''
_RUN_MULTI_NEW = '''        if len(paths) < 2:
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
'''

# --- 4. MainWindow: проверка размера JSON ---
_MAIN_OPEN_OLD = '''        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(
                self,
                tr("error.read.title"),
                tr("error.read.body", type=type(e).__name__, message=str(e)),
            )
            return
'''
_MAIN_OPEN_NEW = '''        if not path:
            return

        p = Path(path)
        # Защита от больших JSON: > 100 МБ — предупредить.
        _JSON_LIMIT_MB = 100
        try:
            size_mb = p.stat().st_size / (1024 * 1024)
        except OSError:
            size_mb = 0
        if size_mb > _JSON_LIMIT_MB:
            answer = QMessageBox.question(
                self,
                tr("error.large_json_title"),
                tr("error.large_json_body",
                   size=size_mb, limit=_JSON_LIMIT_MB),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(
                self,
                tr("error.read.title"),
                tr("error.read.body", type=type(e).__name__, message=str(e)),
            )
            return
'''


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_RU, _RU_OLD, _RU_NEW, required=False): changed = True
    if patch(root, REL_EN, _EN_OLD, _EN_NEW, required=False): changed = True
    if patch(root, REL_DROP, _DROP_IMPORTS_OLD, _DROP_IMPORTS_NEW, required=False): changed = True
    if patch(root, REL_DROP, _DROP_EMIT_OLD, _DROP_EMIT_NEW, required=False): changed = True
    if patch(root, REL_RUN, _RUN_MULTI_OLD, _RUN_MULTI_NEW, required=False): changed = True
    if patch(root, REL_MAIN, _MAIN_OPEN_OLD, _MAIN_OPEN_NEW, required=False): changed = True

    if not fix_utils.DRY_RUN:
        if "_MAX_PCAP_WARN_MB" not in (root / REL_DROP).read_text(encoding="utf-8"):
            raise FixError(f"{REL_DROP}: не удалось применить")
        if "_JSON_LIMIT_MB" not in (root / REL_MAIN).read_text(encoding="utf-8"):
            raise FixError(f"{REL_MAIN}: не удалось применить")
    return changed
