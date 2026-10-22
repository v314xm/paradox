# tools/fix_11_i18n_dialogs.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "11-i18n-dialogs"
TITLE = "i18n: перевод Экспорта, DiffView и диалогов деталей"
REL_RU = "paradox_gui/i18n/_ru.py"
REL_EN = "paradox_gui/i18n/_en.py"

REL_EXPORT = "paradox_gui/views/export_view.py"
REL_DIFF = "paradox_gui/views/diff_view.py"
REL_FINDING = "paradox_gui/dialogs/finding_dialog.py"
REL_CONTRA = "paradox_gui/dialogs/contradiction_dialog.py"
REL_CARVED = "paradox_gui/dialogs/carved_files_dialog.py"

# --- 1. Добавить ключи в _ru.py ---
_RU_OLD = '''    "quick_check.auto": "Авто",

}'''
_RU_NEW = '''    "quick_check.auto": "Авто",

    # --- Export ---
    "export.title": "Экспорт данных (SIEM / Threat Intelligence)",
    "export.subtitle": "Вы можете выгрузить Findings и IOC в формате CSV (для Excel) или STIX 2.1 (для SIEM/EDR).",
    "export.fmt_csv": "CSV (Findings)",
    "export.fmt_stix": "STIX 2.1 (IOC Bundle)",
    "export.copy": "Копировать в буфер",
    "export.save": "Сохранить в файл...",
    "export.empty": "Нет данных. Сначала выполните анализ pcap.",
    "export.copied": "Полные данные скопированы в буфер обмена.\\nМожно вставлять в SIEM или текстовый редактор.",
    "export.csv_saved": "CSV успешно сохранен.",
    "export.stix_saved": "STIX Bundle успешно сохранен.",
    "export.err_save": "Ошибка сохранения",

    # --- Diff ---
    "diff.title": "Сравнение прогонов",
    "diff.subtitle": "Загрузите два JSON-отчёта (старый и новый) — увидите, что добавилось, что исчезло, что изменилось. Удобно при повторном триаже одного и того же pcap через день/неделю.",
    "diff.load_old": "Загрузить старый…",
    "diff.load_new": "Загрузить новый…",
    "diff.placeholder": "Загрузите оба отчёта, чтобы увидеть сравнение.",
    "diff.export_md": "Экспорт в Markdown…",
    "diff.err_file": "Ошибка чтения",
    "diff.wrong_file": "Не тот файл",
    "diff.wrong_file_body": "Не JSON-отчёт Paradox: нет ключа 'findings'.",
    "diff.expected_json": "Ожидается JSON-отчёт.",
    "diff.not_paradox": "Это не JSON-отчёт Paradox.",
    "diff.no_changes": "Изменений нет",

    # --- Finding Dialog ---
    "finding.title": "Finding: {type}",
    "finding.value": "Значение",
    "finding.mitre": "MITRE",
    "finding.reasons": "Почему такая уверенность",
    "finding.evidence": "Evidence",
    "finding.no_reasons": "Нет детального разбора (старый детектор или нет причин).",
    "finding.evidence_empty": "Evidence пусто.",
    "finding.close": "Закрыть",

    # --- Contradiction Dialog ---
    "contra.title": "{rule} — {subject}",
    "contra.resolution": "Разрешение",
    "contra.facts": "Факты",
    "contra.causes": "Возможные причины",
    "contra.not_specified": "Не указано.",
    "contra.no_facts": "Фактов нет.",
    "contra.close": "Закрыть",

    # --- Carved Files ---
    "carved.title": "Извлечённые файлы (Carved Files)",
    "carved.warning": "<b>⚠️ ВНИМАНИЕ!</b> Эти файлы извлечены из перехваченного сетевого трафика. Они могут содержать вредоносное ПО.<br>Не открывайте их на рабочей машине без проверки в изолированной среде (Sandbox / VM).",
    "carved.empty": "В этом прогоне файлы не извлекались.",
    "carved.col_sha": "SHA256",
    "carved.col_ext": "Тип",
    "carved.col_size": "Размер",
    "carved.col_uri": "URI",
    "carved.col_status": "Статус",
    "carved.status_saved": "Сохранён на диск",
    "carved.status_meta": "Только метаданные",
    "carved.open_dir": "Открыть папку с файлами",
    "carved.close": "Закрыть",
    "carved.not_saved_title": "Файл не сохранён",
    "carved.not_saved_body": "Тело файла не сохранено на диск. Включите «Сохранять тела файлов на диск» в Настройках → Производительность и запустите анализ заново.",

}'''

# --- 2. Добавить ключи в _en.py ---
_EN_OLD = '''    "quick_check.auto": "Auto",

}'''
_EN_NEW = '''    "quick_check.auto": "Auto",

    # --- Export ---
    "export.title": "Data Export (SIEM / Threat Intelligence)",
    "export.subtitle": "You can export Findings and IOCs as CSV (for Excel) or STIX 2.1 (for SIEM/EDR).",
    "export.fmt_csv": "CSV (Findings)",
    "export.fmt_stix": "STIX 2.1 (IOC Bundle)",
    "export.copy": "Copy to clipboard",
    "export.save": "Save to file...",
    "export.empty": "No data. Run pcap analysis first.",
    "export.copied": "Full data copied to clipboard.\\nCan be pasted into SIEM or a text editor.",
    "export.csv_saved": "CSV successfully saved.",
    "export.stix_saved": "STIX Bundle successfully saved.",
    "export.err_save": "Save error",

    # --- Diff ---
    "diff.title": "Run Comparison",
    "diff.subtitle": "Load two JSON reports (old and new) to see what was added, removed, or changed. Useful for re-triaging the same pcap days/weeks later.",
    "diff.load_old": "Load old…",
    "diff.load_new": "Load new…",
    "diff.placeholder": "Load both reports to see the comparison.",
    "diff.export_md": "Export to Markdown…",
    "diff.err_file": "Read error",
    "diff.wrong_file": "Wrong file",
    "diff.wrong_file_body": "Not a Paradox JSON report: missing 'findings'.",
    "diff.expected_json": "Expected a JSON report.",
    "diff.not_paradox": "This is not a Paradox JSON report.",
    "diff.no_changes": "No changes",

    # --- Finding Dialog ---
    "finding.title": "Finding: {type}",
    "finding.value": "Value",
    "finding.mitre": "MITRE",
    "finding.reasons": "Confidence reasons",
    "finding.evidence": "Evidence",
    "finding.no_reasons": "No detailed breakdown (old detector or no reasons).",
    "finding.evidence_empty": "Evidence is empty.",
    "finding.close": "Close",

    # --- Contradiction Dialog ---
    "contra.title": "{rule} — {subject}",
    "contra.resolution": "Resolution",
    "contra.facts": "Facts",
    "contra.causes": "Likely causes",
    "contra.not_specified": "Not specified.",
    "contra.no_facts": "No facts.",
    "contra.close": "Close",

    # --- Carved Files ---
    "carved.title": "Carved Files",
    "carved.warning": "<b>⚠️ WARNING!</b> These files were extracted from captured network traffic. They may contain malware.<br>Do not open them on a production machine without checking in an isolated environment (Sandbox / VM).",
    "carved.empty": "No files were extracted in this run.",
    "carved.col_sha": "SHA256",
    "carved.col_ext": "Type",
    "carved.col_size": "Size",
    "carved.col_uri": "URI",
    "carved.col_status": "Status",
    "carved.status_saved": "Saved to disk",
    "carved.status_meta": "Metadata only",
    "carved.open_dir": "Open files folder",
    "carved.close": "Close",
    "carved.not_saved_title": "File not saved",
    "carved.not_saved_body": "File body was not saved to disk. Enable 'Write file bodies to disk' in Settings → Performance and re-run analysis.",

}'''

# --- 3. ExportView ---
_EXP_IMPORTS_OLD = '''import csv
import html
import json
import re
import uuid
from datetime import UTC, datetime'''
_EXP_IMPORTS_NEW = '''import csv
import html
import json
import re
import uuid
from datetime import UTC, datetime

from paradox_gui.i18n import tr'''

_EXP_TITLE_OLD = '''        lbl = QLabel("Экспорт данных (SIEM / Threat Intelligence)")
        lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        layout.addWidget(lbl)

        info = QLabel("Вы можете выгрузить Findings и IOC в формате CSV (для Excel) или STIX 2.1 (для SIEM/EDR).")'''
_EXP_TITLE_NEW = '''        lbl = QLabel(tr("export.title"))
        lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        layout.addWidget(lbl)

        info = QLabel(tr("export.subtitle"))'''

_EXP_FMT_OLD = '''        self.format_combo = QComboBox()
        self.format_combo.addItem("CSV (Findings)", "csv")
        self.format_combo.addItem("STIX 2.1 (IOC Bundle)", "stix")'''
_EXP_FMT_NEW = '''        self.format_combo = QComboBox()
        self.format_combo.addItem(tr("export.fmt_csv"), "csv")
        self.format_combo.addItem(tr("export.fmt_stix"), "stix")'''

_EXP_BTN_OLD = '''        self.btn_copy = QPushButton("Копировать в буфер")'''
_EXP_BTN_NEW = '''        self.btn_copy = QPushButton(tr("export.copy"))'''

_EXP_BTN2_OLD = '''        self.btn_export = QPushButton("Сохранить в файл...")'''
_EXP_BTN2_NEW = '''        self.btn_export = QPushButton(tr("export.save"))'''

_EXP_EMPTY_OLD = '''        self.preview.setHtml("<p style='color:#888;'>Нет данных. Сначала выполните анализ pcap.</p>")'''
_EXP_EMPTY_NEW = '''        self.preview.setHtml(f"<p style='color:#888;'>{tr('export.empty')}</p>")'''

_EXP_COPY_OLD = '''        QMessageBox.information(self, "Успех", "Полные данные скопированы в буфер обмена.\\nМожно вставлять в SIEM или текстовый редактор.")'''
_EXP_COPY_NEW = '''        QMessageBox.information(self, "Success", tr("export.copied"))'''

_EXP_SAVE_CSV_OLD = '''                QMessageBox.information(self, "Успех", "CSV успешно сохранен.")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))
        else:'''
_EXP_SAVE_CSV_NEW = '''                QMessageBox.information(self, "Success", tr("export.csv_saved"))
            except Exception as e:
                QMessageBox.critical(self, tr("export.err_save"), str(e))
        else:'''

_EXP_SAVE_STIX_OLD = '''                QMessageBox.information(self, "Успех", "STIX Bundle успешно сохранен.")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))'''
_EXP_SAVE_STIX_NEW = '''                QMessageBox.information(self, "Success", tr("export.stix_saved"))
            except Exception as e:
                QMessageBox.critical(self, tr("export.err_save"), str(e))'''

# --- 4. DiffView ---
_DIFF_IMPORTS_OLD = '''from paradox_gui.analyzers.run_diff import diff_reports, render_diff_markdown'''
_DIFF_IMPORTS_NEW = '''from paradox_gui.analyzers.run_diff import diff_reports, render_diff_markdown
from paradox_gui.i18n import tr'''

_DIFF_TITLE_OLD = '''        title = QLabel("Сравнение прогонов")
        title.setObjectName("h1")
        outer.addWidget(title)

        hint = QLabel(
            "Загрузите два JSON-отчёта (старый и новый) — увидите, что "
            "добавилось, что исчезло, что изменилось. Удобно при повторном "
            "триаже одного и того же pcap через день/неделю."
        )'''
_DIFF_TITLE_NEW = '''        title = QLabel(tr("diff.title"))
        title.setObjectName("h1")
        outer.addWidget(title)

        hint = QLabel(tr("diff.subtitle"))'''

_DIFF_BTN_OLD = '''        self._btn_old = QPushButton("Загрузить старый…")'''
_DIFF_BTN_NEW = '''        self._btn_old = QPushButton(tr("diff.load_old"))'''

_DIFF_BTN2_OLD = '''        self._btn_new = QPushButton("Загрузить новый…")'''
_DIFF_BTN2_NEW = '''        self._btn_new = QPushButton(tr("diff.load_new"))'''

_DIFF_SUMM_OLD = '''        self._summary = QLabel("Загрузите оба отчёта, чтобы увидеть сравнение.")'''
_DIFF_SUMM_NEW = '''        self._summary = QLabel(tr("diff.placeholder"))'''

_DIFF_EXP_OLD = '''        self._btn_export = QPushButton("Экспорт в Markdown…")'''
_DIFF_EXP_NEW = '''        self._btn_export = QPushButton(tr("diff.export_md"))'''

_DIFF_ERR_OLD = '''            QMessageBox.critical(self, "Ошибка", f"{type(e).__name__}: {e}")
            return
        if not isinstance(data, dict) or "findings" not in data:
            QMessageBox.critical(
                self, "Не тот файл",
                "Не JSON-отчёт Paradox: нет ключа 'findings'.",
            )'''
_DIFF_ERR_NEW = '''            QMessageBox.critical(self, tr("diff.err_file"), f"{type(e).__name__}: {e}")
            return
        if not isinstance(data, dict) or "findings" not in data:
            QMessageBox.critical(
                self, tr("diff.wrong_file"),
                tr("diff.wrong_file_body"),
            )'''

_DIFF_DRAG_OLD = '''        if not path.lower().endswith('.json'):
            QMessageBox.warning(self, 'Ошибка', 'Ожидается JSON-отчёт.')
            return

        try:
            data = json.loads(Path(path).read_text(encoding='utf-8'))
        except Exception as e:
            QMessageBox.critical(self, 'Ошибка', f'Ошибка чтения: {e}')
            return

        if not isinstance(data, dict) or 'findings' not in data:
            QMessageBox.critical(self, 'Не тот файл', 'Это не JSON-отчёт Paradox.')'''
_DIFF_DRAG_NEW = '''        if not path.lower().endswith('.json'):
            QMessageBox.warning(self, tr("diff.err_file"), tr("diff.expected_json"))
            return

        try:
            data = json.loads(Path(path).read_text(encoding='utf-8'))
        except Exception as e:
            QMessageBox.critical(self, tr("diff.err_file"), f'{e}')
            return

        if not isinstance(data, dict) or 'findings' not in data:
            QMessageBox.critical(self, tr("diff.wrong_file"), tr("diff.not_paradox"))'''

_DIFF_NO_CH_OLD = '''        if not d.has_changes():
            self._tree.addTopLevelItem(
                QTreeWidgetItem(["Изменений нет", "", ""])
            )'''
_DIFF_NO_CH_NEW = '''        if not d.has_changes():
            self._tree.addTopLevelItem(
                QTreeWidgetItem([tr("diff.no_changes"), "", ""])
            )'''

# --- 5. FindingDialog ---
_FIND_IMPORTS_OLD = '''from PySide6.QtCore import Qt'''
_FIND_IMPORTS_NEW = '''from PySide6.QtCore import Qt
from paradox_gui.i18n import tr'''

_FIND_TITLE_OLD = '''        self.setWindowTitle(f"Finding: {ftype}")'''
_FIND_TITLE_NEW = '''        self.setWindowTitle(tr("finding.title", type=ftype))'''

_FIND_SECTIONS_OLD = '''        outer.addWidget(self._section_label("Значение"))
        outer.addWidget(self._build_value())
        outer.addWidget(self._section_label("MITRE"))
        outer.addWidget(self._build_mitre())
        outer.addWidget(self._section_label("Почему такая уверенность"))
        outer.addWidget(self._build_confidence_reasons())
        outer.addWidget(self._section_label("Evidence"))'''
_FIND_SECTIONS_NEW = '''        outer.addWidget(self._section_label(tr("finding.value")))
        outer.addWidget(self._build_value())
        outer.addWidget(self._section_label(tr("finding.mitre")))
        outer.addWidget(self._build_mitre())
        outer.addWidget(self._section_label(tr("finding.reasons")))
        outer.addWidget(self._build_confidence_reasons())
        outer.addWidget(self._section_label(tr("finding.evidence")))'''

_FIND_NO_REASONS_OLD = '''            empty = QLabel("Нет детального разбора (старый детектор или нет причин).")'''
_FIND_NO_REASONS_NEW = '''            empty = QLabel(tr("finding.no_reasons"))'''

_FIND_EV_EMPTY_OLD = '''            empty = QLabel("Evidence пусто.")'''
_FIND_EV_EMPTY_NEW = '''            empty = QLabel(tr("finding.evidence_empty"))'''

_FIND_CLOSE_OLD = '''        close = QPushButton("Закрыть")'''
_FIND_CLOSE_NEW = '''        close = QPushButton(tr("finding.close"))'''

# --- 6. ContradictionDialog ---
_CONTRA_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)'''
_CONTRA_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr'''

_CONTRA_TITLE_OLD = '''        self.setWindowTitle(f"{rule} — {subject}")'''
_CONTRA_TITLE_NEW = '''        self.setWindowTitle(tr("contra.title", rule=rule, subject=subject))'''

_CONTRA_SECTIONS_OLD = '''        outer.addWidget(self._build_header())
        outer.addWidget(self._section_label("Разрешение"))
        outer.addWidget(self._build_resolution())
        outer.addWidget(self._section_label("Факты"))
        outer.addWidget(self._build_facts(), stretch=1)
        outer.addWidget(self._section_label("Возможные причины"))'''
_CONTRA_SECTIONS_NEW = '''        outer.addWidget(self._build_header())
        outer.addWidget(self._section_label(tr("contra.resolution")))
        outer.addWidget(self._build_resolution())
        outer.addWidget(self._section_label(tr("contra.facts")))
        outer.addWidget(self._build_facts(), stretch=1)
        outer.addWidget(self._section_label(tr("contra.causes")))'''

_CONTRA_NOT_SPEC_OLD = '''            or "Не указано."
        )'''
_CONTRA_NOT_SPEC_NEW = '''            or tr("contra.not_specified")
        )'''

_CONTRA_NO_FACTS_OLD = '''            empty = QLabel("Фактов нет.")'''
_CONTRA_NO_FACTS_NEW = '''            empty = QLabel(tr("contra.no_facts"))'''

_CONTRA_NOT_SPEC2_OLD = '''        if not causes:
            lbl = QLabel("Не указано.")'''
_CONTRA_NOT_SPEC2_NEW = '''        if not causes:
            lbl = QLabel(tr("contra.not_specified"))'''

_CONTRA_CLOSE_OLD = '''        close = QPushButton("Закрыть")'''
_CONTRA_CLOSE_NEW = '''        close = QPushButton(tr("contra.close"))'''

# --- 7. CarvedFilesDialog ---
_CARVED_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)'''
_CARVED_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from paradox_gui.i18n import tr'''

_CARVED_TITLE_OLD = '''        self.setWindowTitle("Извлечённые файлы (Carved Files)")'''
_CARVED_TITLE_NEW = '''        self.setWindowTitle(tr("carved.title"))'''

_CARVED_WARN_OLD = '''        lbl_warn = QLabel(
            "<b>⚠️ ВНИМАНИЕ!</b> Эти файлы извлечены из перехваченного "
            "сетевого трафика. Они могут содержать вредоносное ПО.<br>"
            "Не открывайте их на рабочей машине без проверки "
            "в изолированной среде (Sandbox / VM)."
        )'''
_CARVED_WARN_NEW = '''        lbl_warn = QLabel(tr("carved.warning"))'''

_CARVED_EMPTY_OLD = '''            empty = QLabel("В этом прогоне файлы не извлекались.")'''
_CARVED_EMPTY_NEW = '''            empty = QLabel(tr("carved.empty"))'''

_CARVED_HEADERS_OLD = '''        self.table.setHorizontalHeaderLabels(
            ["SHA256", "Тип", "Размер", "URI", "Статус"]
        )'''
_CARVED_HEADERS_NEW = '''        self.table.setHorizontalHeaderLabels([
            tr("carved.col_sha"), tr("carved.col_ext"),
            tr("carved.col_size"), tr("carved.col_uri"),
            tr("carved.col_status")
        ])'''

_CARVED_STATUS_OLD = '''                st_item = QTableWidgetItem("Сохранён на диск")'''
_CARVED_STATUS_NEW = '''                st_item = QTableWidgetItem(tr("carved.status_saved"))'''

_CARVED_STATUS2_OLD = '''                st_item = QTableWidgetItem("Только метаданные")'''
_CARVED_STATUS2_NEW = '''                st_item = QTableWidgetItem(tr("carved.status_meta"))'''

_CARVED_OPEN_OLD = '''            open_dir = QPushButton("Открыть папку с файлами")'''
_CARVED_OPEN_NEW = '''            open_dir = QPushButton(tr("carved.open_dir"))'''

_CARVED_CLOSE_OLD = '''        close_btn = QPushButton("Закрыть")'''
_CARVED_CLOSE_NEW = '''        close_btn = QPushButton(tr("carved.close"))'''

_CARVED_NOT_SAVED_OLD = '''            QMessageBox.information(
                self, "Файл не сохранён",
                "Тело файла не сохранено на диск. "
                "Включите «Сохранять тела файлов на диск» "
                "в Настройках → Производительность и запустите анализ заново.",
            )'''
_CARVED_NOT_SAVED_NEW = '''            QMessageBox.information(
                self, tr("carved.not_saved_title"),
                tr("carved.not_saved_body"),
            )'''


def apply(root: Path) -> bool:
    changed = False

    # RU/EN
    if patch(root, REL_RU, _RU_OLD, _RU_NEW, required=False): changed = True
    if patch(root, REL_EN, _EN_OLD, _EN_NEW, required=False): changed = True

    # ExportView
    for old, new in [
        (_EXP_IMPORTS_OLD, _EXP_IMPORTS_NEW),
        (_EXP_TITLE_OLD, _EXP_TITLE_NEW),
        (_EXP_FMT_OLD, _EXP_FMT_NEW),
        (_EXP_BTN_OLD, _EXP_BTN_NEW),
        (_EXP_BTN2_OLD, _EXP_BTN2_NEW),
        (_EXP_EMPTY_OLD, _EXP_EMPTY_NEW),
        (_EXP_COPY_OLD, _EXP_COPY_NEW),
        (_EXP_SAVE_CSV_OLD, _EXP_SAVE_CSV_NEW),
        (_EXP_SAVE_STIX_OLD, _EXP_SAVE_STIX_NEW),
    ]:
        if patch(root, REL_EXPORT, old, new, required=False): changed = True

    # DiffView
    for old, new in [
        (_DIFF_IMPORTS_OLD, _DIFF_IMPORTS_NEW),
        (_DIFF_TITLE_OLD, _DIFF_TITLE_NEW),
        (_DIFF_BTN_OLD, _DIFF_BTN_NEW),
        (_DIFF_BTN2_OLD, _DIFF_BTN2_NEW),
        (_DIFF_SUMM_OLD, _DIFF_SUMM_NEW),
        (_DIFF_EXP_OLD, _DIFF_EXP_NEW),
        (_DIFF_ERR_OLD, _DIFF_ERR_NEW),
        (_DIFF_DRAG_OLD, _DIFF_DRAG_NEW),
        (_DIFF_NO_CH_OLD, _DIFF_NO_CH_NEW),
    ]:
        if patch(root, REL_DIFF, old, new, required=False): changed = True

    # FindingDialog
    for old, new in [
        (_FIND_IMPORTS_OLD, _FIND_IMPORTS_NEW),
        (_FIND_TITLE_OLD, _FIND_TITLE_NEW),
        (_FIND_SECTIONS_OLD, _FIND_SECTIONS_NEW),
        (_FIND_NO_REASONS_OLD, _FIND_NO_REASONS_NEW),
        (_FIND_EV_EMPTY_OLD, _FIND_EV_EMPTY_NEW),
        (_FIND_CLOSE_OLD, _FIND_CLOSE_NEW),
    ]:
        if patch(root, REL_FINDING, old, new, required=False): changed = True

    # ContradictionDialog
    for old, new in [
        (_CONTRA_IMPORTS_OLD, _CONTRA_IMPORTS_NEW),
        (_CONTRA_TITLE_OLD, _CONTRA_TITLE_NEW),
        (_CONTRA_SECTIONS_OLD, _CONTRA_SECTIONS_NEW),
        (_CONTRA_NOT_SPEC_OLD, _CONTRA_NOT_SPEC_NEW),
        (_CONTRA_NO_FACTS_OLD, _CONTRA_NO_FACTS_NEW),
        (_CONTRA_NOT_SPEC2_OLD, _CONTRA_NOT_SPEC2_NEW),
        (_CONTRA_CLOSE_OLD, _CONTRA_CLOSE_NEW),
    ]:
        if patch(root, REL_CONTRA, old, new, required=False): changed = True

    # CarvedFilesDialog
    for old, new in [
        (_CARVED_IMPORTS_OLD, _CARVED_IMPORTS_NEW),
        (_CARVED_TITLE_OLD, _CARVED_TITLE_NEW),
        (_CARVED_WARN_OLD, _CARVED_WARN_NEW),
        (_CARVED_EMPTY_OLD, _CARVED_EMPTY_NEW),
        (_CARVED_HEADERS_OLD, _CARVED_HEADERS_NEW),
        (_CARVED_STATUS_OLD, _CARVED_STATUS_NEW),
        (_CARVED_STATUS2_OLD, _CARVED_STATUS2_NEW),
        (_CARVED_OPEN_OLD, _CARVED_OPEN_NEW),
        (_CARVED_CLOSE_OLD, _CARVED_CLOSE_NEW),
        (_CARVED_NOT_SAVED_OLD, _CARVED_NOT_SAVED_NEW),
    ]:
        if patch(root, REL_CARVED, old, new, required=False): changed = True

    if not fix_utils.DRY_RUN:
        for rel in (REL_RU, REL_EN):
            text = (root / rel).read_text(encoding="utf-8")
            if "export.copied" not in text:
                raise FixError(f"{rel}: не удалось применить")
        if "diff.export_md" not in (root / REL_DIFF).read_text(encoding="utf-8"):
            raise FixError(f"{REL_DIFF}: не удалось применить")
        if "finding.reasons" not in (root / REL_FINDING).read_text(encoding="utf-8"):
            raise FixError(f"{REL_FINDING}: не удалось применить")
        if "contra.resolution" not in (root / REL_CONTRA).read_text(encoding="utf-8"):
            raise FixError(f"{REL_CONTRA}: не удалось применить")
        if "carved.warning" not in (root / REL_CARVED).read_text(encoding="utf-8"):
            raise FixError(f"{REL_CARVED}: не удалось применить")

    return changed
