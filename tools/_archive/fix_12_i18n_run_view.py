# tools/fix_12_i18n_run_view.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "12-i18n-run-view"
TITLE = "i18n: перевод RunView, DropZone, FindingsTable и панелей"
REL_RU = "paradox_gui/i18n/_ru.py"
REL_EN = "paradox_gui/i18n/_en.py"
REL_RUN = "paradox_gui/views/run_view.py"
REL_DROP = "paradox_gui/widgets/drop_zone.py"
REL_FIND = "paradox_gui/widgets/findings_table.py"
REL_ABS = "paradox_gui/widgets/absence_panel.py"
REL_OBS = "paradox_gui/widgets/observations_panel.py"
REL_HIGH = "paradox_gui/widgets/highlights_panel.py"
REL_CONTRA_SEC = "paradox_gui/widgets/contradictions_section.py"
REL_CONTRA_CARD = "paradox_gui/widgets/contradiction_card.py"

_RU_OLD = '''    "carved.not_saved_body": "Тело файла не сохранено на диск. Включите «Сохранять тела файлов на диск» в Настройках → Производительность и запустите анализ заново.",

}'''
_RU_NEW = '''    "carved.not_saved_body": "Тело файла не сохранено на диск. Включите «Сохранять тела файлов на диск» в Настройках → Производительность и запустите анализ заново.",

    # --- Run View & Widgets ---
    "run.drop_title": "Перетащите pcap сюда",
    "run.drop_hint": "или нажмите, чтобы выбрать файл · Ctrl+O",
    "run.open_pcap_dialog": "Открыть pcap",
    "run.multi_pcap": "Открыть несколько pcap для слияния…",
    "run.stop": "Остановить",
    "run.findings": "Находки (Findings)",
    "run.graph": "Граф связей",
    "run.attack_graph": "Граф атаки",
    "run.files": "Файлы",
    "run.what_if": "What-If (Исключить)",
    "run.reset_filter": "Сбросить фильтр",
    "run.no_file": "Файл не выбран.",
    "run.extracting": "Извлечение · {pct}%",
    "run.extracting_speed": "Извлечение · {pct}% · {speed:.1f} МБ/с · ~{remaining:.0f} с",
    "run.detecting": "Детекторы · {done}/{total}",
    "run.detecting_detail": "Детекторы · {done}/{total} · {detail}",
    "run.contradictions": "Противоречия…",
    "run.reports": "Отчёты…",
    "run.cancelled": "Остановлено пользователем",
    "run.done": "Готово · {findings} findings · {contradictions} противоречий · {duration:.1f} сек",
    "run.loaded": "Загружено · {findings} findings · {contradictions} противоречий",
    "run.error": "Ошибка: {msg}",
    "run.multi_warning_title": "Нужно 2+ файла",
    "run.multi_warning_body": "Выбран 1 файл. Для одиночного анализа — перетащите его в зону выше.",

    # --- Findings Table ---
    "find.search_placeholder": "Поиск по value / типу / MITRE…",
    "find.all_types": "Все типы",
    "find.all_conf": "Conf: все",
    "find.host_story_src": "История хоста (src): {ip}",
    "find.host_story_dst": "История хоста (dst): {ip}",

    # --- Panels ---
    "abs.title": "Аномалии / Оборванные сессии",
    "abs.dns": "DNS без ответа",
    "abs.tcp": "TCP без ответа (SYN)",
    "obs.title": "Что видел инструмент",
    "high.title": "Что привлекло внимание",
    "contra.title": "Противоречия",
    "contra.card_details": "Подробнее",
    "contra.card_no_facts": "Фактов нет.",

}'''

_EN_OLD = '''    "carved.not_saved_body": "File body was not saved to disk. Enable 'Write file bodies to disk' in Settings → Performance and re-run analysis.",

}'''
_EN_NEW = '''    "carved.not_saved_body": "File body was not saved to disk. Enable 'Write file bodies to disk' in Settings → Performance and re-run analysis.",

    # --- Run View & Widgets ---
    "run.drop_title": "Drag & drop pcap here",
    "run.drop_hint": "or click to select a file · Ctrl+O",
    "run.open_pcap_dialog": "Open pcap",
    "run.multi_pcap": "Open multiple pcaps for merge…",
    "run.stop": "Stop",
    "run.findings": "Findings",
    "run.graph": "Topology Graph",
    "run.attack_graph": "Attack Graph",
    "run.files": "Files",
    "run.what_if": "What-If (Exclude)",
    "run.reset_filter": "Reset filter",
    "run.no_file": "No file selected.",
    "run.extracting": "Extracting · {pct}%",
    "run.extracting_speed": "Extracting · {pct}% · {speed:.1f} MB/s · ~{remaining:.0f} s",
    "run.detecting": "Detectors · {done}/{total}",
    "run.detecting_detail": "Detectors · {done}/{total} · {detail}",
    "run.contradictions": "Contradictions…",
    "run.reports": "Reports…",
    "run.cancelled": "Stopped by user",
    "run.done": "Done · {findings} findings · {contradictions} contradictions · {duration:.1f} s",
    "run.loaded": "Loaded · {findings} findings · {contradictions} contradictions",
    "run.error": "Error: {msg}",
    "run.multi_warning_title": "2+ files required",
    "run.multi_warning_body": "1 file selected. For single analysis — drag it into the zone above.",

    # --- Findings Table ---
    "find.search_placeholder": "Search by value / type / MITRE…",
    "find.all_types": "All types",
    "find.all_conf": "Conf: all",
    "find.host_story_src": "Host story (src): {ip}",
    "find.host_story_dst": "Host story (dst): {ip}",

    # --- Panels ---
    "abs.title": "Anomalies / Broken Sessions",
    "abs.dns": "DNS without answer",
    "abs.tcp": "TCP without answer (SYN)",
    "obs.title": "What the tool saw",
    "high.title": "What caught attention",
    "contra.title": "Contradictions",
    "contra.card_details": "Details",
    "contra.card_no_facts": "No facts.",

}'''

# --- RunView ---
_RUN_IMPORTS_OLD = '''from ..widgets.highlights_panel import HighlightsPanel
from ..widgets.observations_panel import ObservationsPanel'''
_RUN_IMPORTS_NEW = '''from ..widgets.highlights_panel import HighlightsPanel
from ..widgets.observations_panel import ObservationsPanel
from paradox_gui.i18n import tr'''

_RUN_MULTI_OLD = '''        self.btn_multi_pcap = _QBtn("Открыть несколько pcap для слияния…")'''
_RUN_MULTI_NEW = '''        self.btn_multi_pcap = _QBtn(tr("run.multi_pcap"))'''

_RUN_STOP_OLD = '''        self.stop_btn = QPushButton("Остановить")'''
_RUN_STOP_NEW = '''        self.stop_btn = QPushButton(tr("run.stop"))'''

_RUN_HEADERS_OLD = '''        lbl_findings = QLabel("Находки (Findings)")'''
_RUN_HEADERS_NEW = '''        lbl_findings = QLabel(tr("run.findings"))'''

_RUN_BTNS_OLD = '''        self.btn_graph = QPushButton("Граф связей")'''
_RUN_BTNS_NEW = '''        self.btn_graph = QPushButton(tr("run.graph"))'''

_RUN_BTNS2_OLD = '''        self.btn_attack_graph = QPushButton("Граф атаки")'''
_RUN_BTNS2_NEW = '''        self.btn_attack_graph = QPushButton(tr("run.attack_graph"))'''

_RUN_BTNS3_OLD = '''        self.btn_carved = QPushButton("Файлы")'''
_RUN_BTNS3_NEW = '''        self.btn_carved = QPushButton(tr("run.files"))'''

_RUN_BTNS4_OLD = '''        self.btn_what_if = QPushButton("What-If (Исключить)")'''
_RUN_BTNS4_NEW = '''        self.btn_what_if = QPushButton(tr("run.what_if"))'''

_RUN_BTNS5_OLD = '''        self.btn_reset_filter = QPushButton("Сбросить фильтр")'''
_RUN_BTNS5_NEW = '''        self.btn_reset_filter = QPushButton(tr("run.reset_filter"))'''

_RUN_STATUS_OLD = '''        self.status_label = QLabel("Файл не выбран.")'''
_RUN_STATUS_NEW = '''        self.status_label = QLabel(tr("run.no_file"))'''

_RUN_MULTI_WARN_OLD = '''            QMessageBox.information(
                self, "Нужно 2+ файла",
                "Выбран 1 файл. Для одиночного анализа — перетащите его в зону выше.",
            )'''
_RUN_MULTI_WARN_NEW = '''            QMessageBox.information(
                self, tr("run.multi_warning_title"),
                tr("run.multi_warning_body"),
            )'''

_RUN_PROGRESS_OLD = '''            self.status_label.setText(
                f"Извлечение · {pct}% · {speed_mbs:.1f} МБ/с · ~{remaining:.0f} с"
            )
        else:
            self.status_label.setText(f"Извлечение · {pct}%")'''
_RUN_PROGRESS_NEW = '''            self.status_label.setText(
                tr("run.extracting_speed", pct=pct, speed=speed_mbs, remaining=remaining)
            )
        else:
            self.status_label.setText(tr("run.extracting", pct=pct))'''

_RUN_PHASE_OLD = '''        if name == "detect":
            label = f"Детекторы · {done}/{total}"
            if detail:
                label += f" · {detail}"
            self.status_label.setText(label)
        elif name == "contradictions":
            self.status_label.setText("Противоречия…")
        elif name == "report":
            self.status_label.setText("Отчёты…")'''
_RUN_PHASE_NEW = '''        if name == "detect":
            if detail:
                self.status_label.setText(tr("run.detecting_detail", done=done, total=total, detail=detail))
            else:
                self.status_label.setText(tr("run.detecting", done=done, total=total))
        elif name == "contradictions":
            self.status_label.setText(tr("run.contradictions"))
        elif name == "report":
            self.status_label.setText(tr("run.reports"))'''

_RUN_CANC_OLD = '''        self.status_label.setText("Остановлено пользователем")'''
_RUN_CANC_NEW = '''        self.status_label.setText(tr("run.cancelled"))'''

_RUN_OK_OLD = '''        self.status_label.setText(
            f"Готово · {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий · "
            f"{s.get('duration_sec', 0):.1f} сек"
        )'''
_RUN_OK_NEW = '''        self.status_label.setText(tr(
            "run.done",
            findings=s.get('findings', 0),
            contradictions=s.get('contradictions', 0),
            duration=s.get('duration_sec', 0),
        ))'''

_RUN_LOAD_OLD = '''        self.status_label.setText(
            f"Загружено · {s.get('findings', 0)} findings · "
            f"{s.get('contradictions', 0)} противоречий"
        )'''
_RUN_LOAD_NEW = '''        self.status_label.setText(tr(
            "run.loaded",
            findings=s.get('findings', 0),
            contradictions=s.get('contradictions', 0),
        ))'''

_RUN_ERR_OLD = '''        self.status_label.setText(f"Ошибка: {msg}")'''
_RUN_ERR_NEW = '''        self.status_label.setText(tr("run.error", msg=msg))'''

# --- DropZone ---
_DROP_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QLabel,
    QVBoxLayout,
)'''
_DROP_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QLabel,
    QVBoxLayout,
)
from paradox_gui.i18n import tr'''

_DROP_TITLE_OLD = '''        self._title = QLabel("Перетащите pcap сюда")'''
_DROP_TITLE_NEW = '''        self._title = QLabel(tr("run.drop_title"))'''

_DROP_HINT_OLD = '''        self._hint = QLabel("или нажмите, чтобы выбрать файл · Ctrl+O")'''
_DROP_HINT_NEW = '''        self._hint = QLabel(tr("run.drop_hint"))'''

_DROP_DIALOG_OLD = '''            "Открыть pcap",
            "",
            "Packet captures (*.pcap *.pcapng *.cap);;Все файлы (*)",'''
_DROP_DIALOG_NEW = '''            tr("run.open_pcap_dialog"),
            "",
            "Packet captures (*.pcap *.pcapng *.cap);;All files (*)",'''

# --- FindingsTable ---
_FIND_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)'''
_FIND_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)
from paradox_gui.i18n import tr'''

_FIND_SEARCH_OLD = '''        self._search.setPlaceholderText("Поиск по value / типу / MITRE…")'''
_FIND_SEARCH_NEW = '''        self._search.setPlaceholderText(tr("find.search_placeholder"))'''

_FIND_TYPES_OLD = '''        self._type_filter.addItem("Все типы", None)'''
_FIND_TYPES_NEW = '''        self._type_filter.addItem(tr("find.all_types"), None)'''

_FIND_CONF_OLD = '''        self._conf_filter.addItem("Conf: все", None)'''
_FIND_CONF_NEW = '''        self._conf_filter.addItem(tr("find.all_conf"), None)'''

_FIND_CTX_OLD = '''        if src:
            act_src = menu.addAction(f"История хоста (src): {src}")
            act_src.triggered.connect(lambda: self.host_story_requested.emit(src))
        if dst:
            act_dst = menu.addAction(f"История хоста (dst): {dst}")
            act_dst.triggered.connect(lambda: self.host_story_requested.emit(dst))'''
_FIND_CTX_NEW = '''        if src:
            act_src = menu.addAction(tr("find.host_story_src", ip=src))
            act_src.triggered.connect(lambda: self.host_story_requested.emit(src))
        if dst:
            act_dst = menu.addAction(tr("find.host_story_dst", ip=dst))
            act_dst.triggered.connect(lambda: self.host_story_requested.emit(dst))'''

# --- Panels ---
_ABS_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QFrame,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)'''
_ABS_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QFrame,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from paradox_gui.i18n import tr'''

_ABS_TITLE_OLD = '''        title = QLabel("Аномалии / Оборванные сессии")'''
_ABS_TITLE_NEW = '''        title = QLabel(tr("abs.title"))'''

_ABS_DNS_OLD = '''        self.tabs.addTab(self.tab_dns, "DNS без ответа")'''
_ABS_DNS_NEW = '''        self.tabs.addTab(self.tab_dns, tr("abs.dns"))'''

_ABS_TCP_OLD = '''        self.tabs.addTab(self.tab_tcp, "TCP без ответа (SYN)")'''
_ABS_TCP_NEW = '''        self.tabs.addTab(self.tab_tcp, tr("abs.tcp"))'''

_OBS_IMPORTS_OLD = '''from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout'''
_OBS_IMPORTS_NEW = '''from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout
from paradox_gui.i18n import tr'''

_OBS_TITLE_OLD = '''        title = QLabel("Что видел инструмент")'''
_OBS_TITLE_NEW = '''        title = QLabel(tr("obs.title"))'''

_HIGH_IMPORTS_OLD = '''from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout'''
_HIGH_IMPORTS_NEW = '''from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout
from paradox_gui.i18n import tr'''

_HIGH_TITLE_OLD = '''        title = QLabel("Что привлекло внимание")'''
_HIGH_TITLE_NEW = '''        title = QLabel(tr("high.title"))'''

_CONTRA_SEC_OLD = '''from paradox_gui.widgets.contradiction_card import ContradictionCard'''
_CONTRA_SEC_NEW = '''from paradox_gui.i18n import tr
from paradox_gui.widgets.contradiction_card import ContradictionCard'''

_CONTRA_SEC_TITLE_OLD = '''        title = QLabel("Противоречия")'''
_CONTRA_SEC_TITLE_NEW = '''        title = QLabel(tr("contra.title"))'''

_CONTRA_CARD_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)'''
_CONTRA_CARD_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)
from paradox_gui.i18n import tr'''

_CONTRA_CARD_BTN_OLD = '''        btn = QPushButton("Подробнее")'''
_CONTRA_CARD_BTN_NEW = '''        btn = QPushButton(tr("contra.card_details"))'''

_CONTRA_CARD_EMPTY_OLD = '''            empty = QLabel("Фактов нет.")'''
_CONTRA_CARD_EMPTY_NEW = '''            empty = QLabel(tr("contra.card_no_facts"))'''


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_RU, _RU_OLD, _RU_NEW, required=False): changed = True
    if patch(root, REL_EN, _EN_OLD, _EN_NEW, required=False): changed = True

    for rel, pairs in [
        (REL_RUN,
         [(_RUN_IMPORTS_OLD, _RUN_IMPORTS_NEW), (_RUN_MULTI_OLD, _RUN_MULTI_NEW), (_RUN_STOP_OLD, _RUN_STOP_NEW),
          (_RUN_HEADERS_OLD, _RUN_HEADERS_NEW), (_RUN_BTNS_OLD, _RUN_BTNS_NEW), (_RUN_BTNS2_OLD, _RUN_BTNS2_NEW),
          (_RUN_BTNS3_OLD, _RUN_BTNS3_NEW), (_RUN_BTNS4_OLD, _RUN_BTNS4_NEW), (_RUN_BTNS5_OLD, _RUN_BTNS5_NEW),
          (_RUN_STATUS_OLD, _RUN_STATUS_NEW), (_RUN_MULTI_WARN_OLD, _RUN_MULTI_WARN_NEW),
          (_RUN_PROGRESS_OLD, _RUN_PROGRESS_NEW), (_RUN_PHASE_OLD, _RUN_PHASE_NEW), (_RUN_CANC_OLD, _RUN_CANC_NEW),
          (_RUN_OK_OLD, _RUN_OK_NEW), (_RUN_LOAD_OLD, _RUN_LOAD_NEW), (_RUN_ERR_OLD, _RUN_ERR_NEW)]),
        (REL_DROP,
         [(_DROP_IMPORTS_OLD, _DROP_IMPORTS_NEW), (_DROP_TITLE_OLD, _DROP_TITLE_NEW), (_DROP_HINT_OLD, _DROP_HINT_NEW),
          (_DROP_DIALOG_OLD, _DROP_DIALOG_NEW)]),
        (REL_FIND, [(_FIND_IMPORTS_OLD, _FIND_IMPORTS_NEW), (_FIND_SEARCH_OLD, _FIND_SEARCH_NEW),
                    (_FIND_TYPES_OLD, _FIND_TYPES_NEW), (_FIND_CONF_OLD, _FIND_CONF_NEW),
                    (_FIND_CTX_OLD, _FIND_CTX_NEW)]),
        (REL_ABS, [(_ABS_IMPORTS_OLD, _ABS_IMPORTS_NEW), (_ABS_TITLE_OLD, _ABS_TITLE_NEW), (_ABS_DNS_OLD, _ABS_DNS_NEW),
                   (_ABS_TCP_OLD, _ABS_TCP_NEW)]),
        (REL_OBS, [(_OBS_IMPORTS_OLD, _OBS_IMPORTS_NEW), (_OBS_TITLE_OLD, _OBS_TITLE_NEW)]),
        (REL_HIGH, [(_HIGH_IMPORTS_OLD, _HIGH_IMPORTS_NEW), (_HIGH_TITLE_OLD, _HIGH_TITLE_NEW)]),
        (REL_CONTRA_SEC, [(_CONTRA_SEC_OLD, _CONTRA_SEC_NEW), (_CONTRA_SEC_TITLE_OLD, _CONTRA_SEC_TITLE_NEW)]),
        (REL_CONTRA_CARD,
         [(_CONTRA_CARD_IMPORTS_OLD, _CONTRA_CARD_IMPORTS_NEW), (_CONTRA_CARD_BTN_OLD, _CONTRA_CARD_BTN_NEW),
          (_CONTRA_CARD_EMPTY_OLD, _CONTRA_CARD_EMPTY_NEW)]),
    ]:
        for old, new in pairs:
            if patch(root, rel, old, new, required=False): changed = True

    if not fix_utils.DRY_RUN:
        if "run.drop_title" not in (root / REL_RU).read_text(encoding="utf-8"):
            raise FixError(f"{REL_RU}: не удалось применить")
        if "run.multi_pcap" not in (root / REL_RUN).read_text(encoding="utf-8"):
            raise FixError(f"{REL_RUN}: не удалось применить")

    return changed
