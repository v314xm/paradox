# tools/fix_10_i18n_tabs.py
from __future__ import annotations
import re
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "10-i18n-tabs"
TITLE = "i18n: перевод TimelineView, HistoryView, QuickCheckWindow"
REL_RU = "paradox_gui/i18n/_ru.py"
REL_EN = "paradox_gui/i18n/_en.py"
REL_TL = "paradox_gui/views/timeline_view.py"
REL_HIST = "paradox_gui/views/history_view.py"
REL_QC = "paradox_gui/views/quick_check_window.py"

# --- 1. RU ---
_RU_OLD = '''    "settings.threatintel.max_iocs": "Максимум IOC за прогон",

}'''
_RU_NEW = '''    "settings.threatintel.max_iocs": "Максимум IOC за прогон",

    # --- Timeline ---
    "timeline.title": "Хронология инцидента по фазам Kill-Chain",
    "timeline.no_events": "Хронология инцидента (событий не найдено)",
    "timeline.events_count": "Хронология инцидента (Событий: {count})",
    "timeline.search_placeholder": "Поиск по IP, типу или MITRE...",
    "timeline.expand_all": "Развернуть все",
    "timeline.collapse_all": "Свернуть все",
    "timeline.no_selection": "Кликните на событие, чтобы увидеть детали.",
    "timeline.phase_selected": "Выбрана фаза. Кликните на конкретное событие.",
    "timeline.phase_label": "Фаза:",
    "timeline.confidence_label": "Confidence:",
    "timeline.reasons_label": "Почему детектор так решил:",
    "timeline.evidence_label": "Дополнительные данные (Evidence):",
    "timeline.description_label": "Полное описание:",

    # --- History ---
    "history.title": "История",
    "history.subtitle": "Прогоны текущей сессии. Клик по записи — детали справа. История не сохраняется между запусками.",
    "history.empty": "Прогонов пока нет. Откройте pcap во вкладке «Прогон».",
    "history.cleared": "История очищена.",
    "history.clear_button": "Очистить историю",
    "history.ctx_compare": "Сравнить с текущим прогоном…",

    # --- QuickCheck ---
    "quick_check.title": "Проверить IOC",
    "quick_check.subtitle": "Введите IP, домен, URL или SHA256. Тип определится автоматически. Опрошены будут все включённые провайдеры.",
    "quick_check.input_placeholder": "8.8.8.8 · evil.com · https://evil.com/x · <sha256>",
    "quick_check.check_button": "Проверить",
    "quick_check.from_last_run": "Из последнего прогона:",
    "quick_check.no_data": "— нет данных —",
    "quick_check.no_run": "— нет данных (запустите прогон) —",
    "quick_check.no_iocs": "— в прогоне нет IOC —",
    "quick_check.select_ioc": "— выберите IOC —",
    "quick_check.type_detected": "Определён тип: {type}",
    "quick_check.type_unknown": "Тип не определён — выберите вручную",
    "quick_check.warning_type": "Тип не определён",
    "quick_check.warning_type_body": "Не удалось автоматически определить тип IOC. Выберите тип в выпадающем списке.",
    "quick_check.no_providers": "Нет провайдеров",
    "quick_check.no_providers_body": "Ни один провайдер не поддерживает тип «{type}». Проверьте Настройки → Threat Intel.",
    "quick_check.querying": "Опрос {count} провайдеров для {ioc} ({type})…",
    "quick_check.done": "Готово: {count} провайдеров ответили для {ioc}.",
    "quick_check.no_results": "Ни один провайдер не ответил.",
    "quick_check.error": "Ошибка: {msg}",
    "quick_check.auto": "Авто",

}'''

# --- 2. EN ---
_EN_OLD = '''    "settings.threatintel.max_iocs": "Max IOCs per run",

}'''
_EN_NEW = '''    "settings.threatintel.max_iocs": "Max IOCs per run",

    # --- Timeline ---
    "timeline.title": "Incident Timeline by Kill-Chain Phase",
    "timeline.no_events": "Incident Timeline (no events found)",
    "timeline.events_count": "Incident Timeline (Events: {count})",
    "timeline.search_placeholder": "Search by IP, type or MITRE...",
    "timeline.expand_all": "Expand all",
    "timeline.collapse_all": "Collapse all",
    "timeline.no_selection": "Click on an event to see details.",
    "timeline.phase_selected": "Phase selected. Click on a specific event.",
    "timeline.phase_label": "Phase:",
    "timeline.confidence_label": "Confidence:",
    "timeline.reasons_label": "Why the detector decided this:",
    "timeline.evidence_label": "Additional data (Evidence):",
    "timeline.description_label": "Full description:",

    # --- History ---
    "history.title": "History",
    "history.subtitle": "Runs in this session. Click an entry to see details. History is not saved between launches.",
    "history.empty": "No runs yet. Open a pcap in the Run tab.",
    "history.cleared": "History cleared.",
    "history.clear_button": "Clear history",
    "history.ctx_compare": "Compare with current run…",

    # --- QuickCheck ---
    "quick_check.title": "Check IOC",
    "quick_check.subtitle": "Enter an IP, domain, URL or SHA256. Type will be detected automatically. All enabled providers will be queried.",
    "quick_check.input_placeholder": "8.8.8.8 · evil.com · https://evil.com/x · <sha256>",
    "quick_check.check_button": "Check",
    "quick_check.from_last_run": "From last run:",
    "quick_check.no_data": "— no data —",
    "quick_check.no_run": "— no data (run analysis first) —",
    "quick_check.no_iocs": "— no IOCs in the last run —",
    "quick_check.select_ioc": "— select an IOC —",
    "quick_check.type_detected": "Detected type: {type}",
    "quick_check.type_unknown": "Type not detected — select manually",
    "quick_check.warning_type": "Type not detected",
    "quick_check.warning_type_body": "Could not detect IOC type automatically. Select a type from the dropdown.",
    "quick_check.no_providers": "No providers",
    "quick_check.no_providers_body": "No provider supports type «{type}». Check Settings → Threat Intel.",
    "quick_check.querying": "Querying {count} providers for {ioc} ({type})…",
    "quick_check.done": "Done: {count} providers responded for {ioc}.",
    "quick_check.no_results": "No provider responded.",
    "quick_check.error": "Error: {msg}",
    "quick_check.auto": "Auto",

}'''

# --- 3. TimelineView ---
_TL_IMPORTS_OLD = '''from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)'''
_TL_IMPORTS_NEW = '''from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr'''

_TL_HEADER_OLD = '''        header_layout = QHBoxLayout()
        self.lbl_info = QLabel("Хронология инцидента по фазам Kill-Chain")
        self.lbl_info.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        header_layout.addWidget(self.lbl_info)
        header_layout.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск по IP, типу или MITRE...")
        self.search_edit.setMinimumWidth(300)
        self.search_edit.textChanged.connect(self._apply_filter)
        header_layout.addWidget(self.search_edit)

        self.btn_expand = QPushButton("Развернуть все")
        self.btn_expand.clicked.connect(lambda: self.tree.expandAll())
        header_layout.addWidget(self.btn_expand)

        self.btn_collapse = QPushButton("Свернуть все")
        self.btn_collapse.clicked.connect(lambda: self.tree.collapseAll())
        header_layout.addWidget(self.btn_collapse)
'''
_TL_HEADER_NEW = '''        header_layout = QHBoxLayout()
        self.lbl_info = QLabel(tr("timeline.title"))
        self.lbl_info.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        header_layout.addWidget(self.lbl_info)
        header_layout.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr("timeline.search_placeholder"))
        self.search_edit.setMinimumWidth(300)
        self.search_edit.textChanged.connect(self._apply_filter)
        header_layout.addWidget(self.search_edit)

        self.btn_expand = QPushButton(tr("timeline.expand_all"))
        self.btn_expand.clicked.connect(lambda: self.tree.expandAll())
        header_layout.addWidget(self.btn_expand)

        self.btn_collapse = QPushButton(tr("timeline.collapse_all"))
        self.btn_collapse.clicked.connect(lambda: self.tree.collapseAll())
        header_layout.addWidget(self.btn_collapse)
'''

_TL_DETAILS_OLD = '''        self.details = QTextBrowser()
        self.details.setStyleSheet("background: #2a2a35; border: 1px solid #444; border-radius: 4px;")
        self.details.setHtml("<p style='color:#888;'>Кликните на событие, чтобы увидеть детали.</p>")
        self.details.setMinimumWidth(350)
        splitter.addWidget(self.details)
'''
_TL_DETAILS_NEW = '''        self.details = QTextBrowser()
        self.details.setStyleSheet("background: #2a2a35; border: 1px solid #444; border-radius: 4px;")
        self.details.setHtml(f"<p style='color:#888;'>{tr('timeline.no_selection')}</p>")
        self.details.setMinimumWidth(350)
        splitter.addWidget(self.details)
'''

_TL_UPDATE_OLD = '''        timeline = report.get("timeline", [])
        if not timeline:
            self.lbl_info.setText("Хронология инцидента (событий не найдено)")
            return

        self.lbl_info.setText(f"Хронология инцидента (Событий: {len(timeline)})")
'''
_TL_UPDATE_NEW = '''        timeline = report.get("timeline", [])
        if not timeline:
            self.lbl_info.setText(tr("timeline.no_events"))
            return

        self.lbl_info.setText(tr("timeline.events_count", count=len(timeline)))
'''

_TL_CLICK_OLD = '''        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            self.details.setHtml("<p style='color:#888;'>Выбрана фаза. Кликните на конкретное событие.</p>")
            return

        html = f"<h2 style='color:#44aaff; margin-bottom:5px;'>{data.get('type', '?')}</h2>"
        html += f"<p><b>Фаза:</b> {data.get('phase', '?')}</p>"

        mitre = data.get('mitre_id')
        html += f"<p><b>MITRE:</b> {mitre if mitre else '—'}</p>"

        conf = data.get("confidence", 0)
        conf_color = "#ff4444" if conf >= 0.85 else "#ffaa00" if conf >= 0.7 else "#44aaff"
        html += f"<p><b>Confidence:</b> <span style='color:{conf_color}; font-weight:bold;'>{conf:.2f}</span></p>"

        reasons = data.get("confidence_reasons") or []
        if reasons:
            html += "<h4 style='color:#aaa;'>Почему детектор так решил:</h4><ul>"
            for r in reasons:
                html += f"<li>{r}</li>"
            html += "</ul>"

        ev = data.get("evidence") or {}
        if ev:
            html += "<h4 style='color:#aaa;'>Дополнительные данные (Evidence):</h4><ul>"
            for k, v in ev.items():
                html += f"<li><b>{k}:</b> {v}</li>"
            html += "</ul>"

        html += f"<hr><h4 style='color:#aaa;'>Полное описание:</h4><p style='line-height:1.4;'>{data.get('description', '')}</p>"
'''
_TL_CLICK_NEW = '''        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            self.details.setHtml(f"<p style='color:#888;'>{tr('timeline.phase_selected')}</p>")
            return

        html = f"<h2 style='color:#44aaff; margin-bottom:5px;'>{data.get('type', '?')}</h2>"
        html += f"<p><b>{tr('timeline.phase_label')}</b> {data.get('phase', '?')}</p>"

        mitre = data.get('mitre_id')
        html += f"<p><b>MITRE:</b> {mitre if mitre else '—'}</p>"

        conf = data.get("confidence", 0)
        conf_color = "#ff4444" if conf >= 0.85 else "#ffaa00" if conf >= 0.7 else "#44aaff"
        html += f"<p><b>{tr('timeline.confidence_label')}</b> <span style='color:{conf_color}; font-weight:bold;'>{conf:.2f}</span></p>"

        reasons = data.get("confidence_reasons") or []
        if reasons:
            html += f"<h4 style='color:#aaa;'>{tr('timeline.reasons_label')}</h4><ul>"
            for r in reasons:
                html += f"<li>{r}</li>"
            html += "</ul>"

        ev = data.get("evidence") or {}
        if ev:
            html += f"<h4 style='color:#aaa;'>{tr('timeline.evidence_label')}</h4><ul>"
            for k, v in ev.items():
                html += f"<li><b>{k}:</b> {v}</li>"
            html += "</ul>"

        html += f"<hr><h4 style='color:#aaa;'>{tr('timeline.description_label')}</h4><p style='line-height:1.4;'>{data.get('description', '')}</p>"
'''

# --- 4. HistoryView ---
_HIST_IMPORTS_OLD = '''from PySide6.QtCore import Qt, Signal
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
)

from paradox_gui.storage import HistoryDB'''
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
)

from paradox_gui.i18n import tr
from paradox_gui.storage import HistoryDB'''

_HIST_TITLE_OLD = '''        title = QLabel("История")
        title.setObjectName("h1")  # QSS-стиль из theme.py
        outer.addWidget(title)

        subtitle = QLabel(
            "Прогоны текущей сессии. Клик по записи — детали справа. "
            "История не сохраняется между запусками."
        )'''
_HIST_TITLE_NEW = '''        title = QLabel(tr("history.title"))
        title.setObjectName("h1")  # QSS-стиль из theme.py
        outer.addWidget(title)

        subtitle = QLabel(tr("history.subtitle"))'''

_HIST_PLACEHOLDER_OLD = '''        self._details.setHtml(
            '<p style="color:#a0a0b0;">Прогонов пока нет. '
            'Откройте pcap во вкладке «Прогон».</p>'
        )'''
_HIST_PLACEHOLDER_NEW = '''        self._details.setHtml(
            f'<p style="color:#a0a0b0;">{tr("history.empty")}</p>'
        )'''

_HIST_CLEAR_BTN_OLD = '''        clear_btn = QPushButton("Очистить историю")'''
_HIST_CLEAR_BTN_NEW = '''        clear_btn = QPushButton(tr("history.clear_button"))'''

_HIST_CLEARED_OLD = '''        self._details.setHtml(
            '<p style="color:#a0a0b0;">История очищена.</p>'
        )'''
_HIST_CLEARED_NEW = '''        self._details.setHtml(
            f'<p style="color:#a0a0b0;">{tr("history.cleared")}</p>'
        )'''

# --- 5. QuickCheckWindow ---
_QC_IMPORTS_OLD = '''from paradox.integrations.cache import EnrichmentCache
from paradox.integrations.registry import REGISTRY
from paradox_gui.ioc_utils import detect_ioc_type, provider_link
from paradox_gui.widgets.provider_card import ProviderCard
from paradox_gui.workers.quick_check_worker import QuickCheckWorker

_AUTO = "Авто"'''
_QC_IMPORTS_NEW = '''from paradox.integrations.cache import EnrichmentCache
from paradox.integrations.registry import REGISTRY
from paradox_gui.i18n import tr
from paradox_gui.ioc_utils import detect_ioc_type, provider_link
from paradox_gui.widgets.provider_card import ProviderCard
from paradox_gui.workers.quick_check_worker import QuickCheckWorker

_AUTO_KEY = "quick_check.auto"'''

_QC_TITLE_OLD = '''        title = QLabel("Проверить IOC")
        title.setObjectName("h1")
        outer.addWidget(title)

        subtitle = QLabel(
            "Введите IP, домен, URL или SHA256. Тип определится "
            "автоматически. Опрошены будут все включённые провайдеры."
        )'''
_QC_TITLE_NEW = '''        title = QLabel(tr("quick_check.title"))
        title.setObjectName("h1")
        outer.addWidget(title)

        subtitle = QLabel(tr("quick_check.subtitle"))'''

_QC_INPUT_OLD = '''        self._type_combo = QComboBox()
        self._type_combo.addItem(_AUTO)
        for t in _TYPES:
            self._type_combo.addItem(t)
        self._type_combo.setFixedWidth(110)
        input_row.addWidget(self._type_combo)

        self._ioc_input = QLineEdit()
        self._ioc_input.setPlaceholderText(
            "8.8.8.8 · evil.com · https://evil.com/x · <sha256>"
        )'''
_QC_INPUT_NEW = '''        self._type_combo = QComboBox()
        self._type_combo.addItem(tr(_AUTO_KEY))
        for t in _TYPES:
            self._type_combo.addItem(t)
        self._type_combo.setFixedWidth(110)
        input_row.addWidget(self._type_combo)

        self._ioc_input = QLineEdit()
        self._ioc_input.setPlaceholderText(tr("quick_check.input_placeholder"))'''

_QC_CHECK_BTN_OLD = '''        self._check_btn = QPushButton("Проверить")'''
_QC_CHECK_BTN_NEW = '''        self._check_btn = QPushButton(tr("quick_check.check_button"))'''

_QC_FROM_OLD = '''        from_lbl = QLabel("Из последнего прогона:")'''
_QC_FROM_NEW = '''        from_lbl = QLabel(tr("quick_check.from_last_run"))'''

_QC_COMBO_INIT_OLD = '''        self._ioc_combo.addItem("— нет данных —")'''
_QC_COMBO_INIT_NEW = '''        self._ioc_combo.addItem(tr("quick_check.no_data"))'''

_QC_REFRESH_OLD = '''        self._ioc_combo.blockSignals(True)
        self._ioc_combo.clear()
        self._ioc_combo.addItem("— выберите IOC —", userData=None)

        if not self._report or not isinstance(self._report, dict):
            self._ioc_combo.addItem("— нет данных (запустите прогон) —")
            self._ioc_combo.setEnabled(False)
            self._ioc_combo.blockSignals(False)
            return
'''
_QC_REFRESH_NEW = '''        self._ioc_combo.blockSignals(True)
        self._ioc_combo.clear()
        self._ioc_combo.addItem(tr("quick_check.select_ioc"), userData=None)

        if not self._report or not isinstance(self._report, dict):
            self._ioc_combo.addItem(tr("quick_check.no_run"))
            self._ioc_combo.setEnabled(False)
            self._ioc_combo.blockSignals(False)
            return
'''

_QC_NO_IOCS_OLD = '''        if not iocs:
            self._ioc_combo.addItem("— в прогоне нет IOC —")
            self._ioc_combo.setEnabled(False)
            self._ioc_combo.blockSignals(False)
            return
'''
_QC_NO_IOCS_NEW = '''        if not iocs:
            self._ioc_combo.addItem(tr("quick_check.no_iocs"))
            self._ioc_combo.setEnabled(False)
            self._ioc_combo.blockSignals(False)
            return
'''

_QC_TYPE_HINT_OLD = '''    def _on_input_changed(self, text: str) -> None:
        t = detect_ioc_type(text)
        if t:
            self._type_hint.setText(f"Определён тип: {t}")
        elif text.strip():
            self._type_hint.setText("Тип не определён — выберите вручную")
        else:
            self._type_hint.setText("")

    def _resolve_type(self) -> str | None:
        cur = self._type_combo.currentText()
        if cur != _AUTO:
            return cur
        return detect_ioc_type(self._ioc_input.text())
'''
_QC_TYPE_HINT_NEW = '''    def _on_input_changed(self, text: str) -> None:
        t = detect_ioc_type(text)
        if t:
            self._type_hint.setText(tr("quick_check.type_detected", type=t))
        elif text.strip():
            self._type_hint.setText(tr("quick_check.type_unknown"))
        else:
            self._type_hint.setText("")

    def _resolve_type(self) -> str | None:
        cur = self._type_combo.currentText()
        if cur != tr(_AUTO_KEY):
            return cur
        return detect_ioc_type(self._ioc_input.text())
'''

_QC_WARN_TYPE_OLD = '''        if ioc_type is None:
            QMessageBox.warning(
                self, "Тип не определён",
                "Не удалось автоматически определить тип IOC. "
                "Выберите тип в выпадающем списке.",
            )
            return
'''
_QC_WARN_TYPE_NEW = '''        if ioc_type is None:
            QMessageBox.warning(
                self, tr("quick_check.warning_type"),
                tr("quick_check.warning_type_body"),
            )
            return
'''

_QC_NO_PROV_OLD = '''        if not providers:
            QMessageBox.information(
                self, "Нет провайдеров",
                f"Ни один провайдер не поддерживает тип «{ioc_type}». "
                f"Проверьте Настройки → Threat Intel.",
            )
            return
'''
_QC_NO_PROV_NEW = '''        if not providers:
            QMessageBox.information(
                self, tr("quick_check.no_providers"),
                tr("quick_check.no_providers_body", type=ioc_type),
            )
            return
'''

_QC_QUERYING_OLD = '''        self._clear_results()
        self._set_busy(True)
        self._status.setText(
            f"Опрос {len(providers)} провайдеров для {ioc} ({ioc_type})…"
        )
'''
_QC_QUERYING_NEW = '''        self._clear_results()
        self._set_busy(True)
        self._status.setText(
            tr("quick_check.querying",
               count=len(providers), ioc=ioc, type=ioc_type)
        )
'''

_QC_NO_RESULTS_OLD = '''        self._set_busy(False)
        if not results:
            self._status.setText("Ни один провайдер не ответил.")
            return
'''
_QC_NO_RESULTS_NEW = '''        self._set_busy(False)
        if not results:
            self._status.setText(tr("quick_check.no_results"))
            return
'''

_QC_DONE_OLD = '''        self._status.setText(
            f"Готово: {len(results)} провайдеров ответили для {ioc}."
        )
'''
_QC_DONE_NEW = '''        self._status.setText(
            tr("quick_check.done", count=len(results), ioc=ioc)
        )
'''

_QC_ERROR_OLD = '''    def _on_failed(self, msg: str) -> None:
        self._set_busy(False)
        self._status.setText(f"Ошибка: {msg}")
'''
_QC_ERROR_NEW = '''    def _on_failed(self, msg: str) -> None:
        self._set_busy(False)
        self._status.setText(tr("quick_check.error", msg=msg))
'''


def _dedupe_context_menu(root: Path) -> bool:
    """Удалить дубликат _on_context_menu в history_view.py.

    fix_06 не идемпотентен: его OLD-паттерн (метод _on_row_changed)
    содержится в конце NEW-паттерна. При повторном применении fix_06
    добавляет вторую копию _on_context_menu.
    """
    hist_path = root / REL_HIST
    if not hist_path.exists():
        return False
    text = hist_path.read_text(encoding="utf-8")
    marker = "    def _on_context_menu(self, pos) -> None:"
    n = text.count(marker)
    if n <= 1:
        return False
    pattern = re.compile(
        r'    def _on_context_menu\(self, pos\) -> None:.*?'
        r'menu\.exec\(self\._list\.viewport\(\)\.mapToGlobal\(pos\)\)\n\n',
        re.DOTALL,
    )
    matches = list(pattern.finditer(text))
    if len(matches) <= 1:
        return False
    for m in reversed(matches[1:]):
        text = text[:m.start()] + text[m.end():]
    if not fix_utils.DRY_RUN:
        hist_path.write_text(text, encoding="utf-8", newline="\n")
    print(f"  [dedup] removed {len(matches) - 1} duplicate _on_context_menu from {REL_HIST}")
    return True


def apply(root: Path) -> bool:
    changed = False

    # Step 0: dedupe duplicate _on_context_menu (see docstring above).
    if _dedupe_context_menu(root):
        changed = True

    # Step 1: RU/EN keys
    if patch(root, REL_RU, _RU_OLD, _RU_NEW, required=False): changed = True
    if patch(root, REL_EN, _EN_OLD, _EN_NEW, required=False): changed = True

    # Step 2: TimelineView
    for old, new in [
        (_TL_IMPORTS_OLD, _TL_IMPORTS_NEW),
        (_TL_HEADER_OLD, _TL_HEADER_NEW),
        (_TL_DETAILS_OLD, _TL_DETAILS_NEW),
        (_TL_UPDATE_OLD, _TL_UPDATE_NEW),
        (_TL_CLICK_OLD, _TL_CLICK_NEW),
    ]:
        if patch(root, REL_TL, old, new, required=False): changed = True

    # Step 3: HistoryView (без _on_context_menu — он обрабатывается отдельно)
    for old, new in [
        (_HIST_IMPORTS_OLD, _HIST_IMPORTS_NEW),
        (_HIST_TITLE_OLD, _HIST_TITLE_NEW),
        (_HIST_PLACEHOLDER_OLD, _HIST_PLACEHOLDER_NEW),
        (_HIST_CLEAR_BTN_OLD, _HIST_CLEAR_BTN_NEW),
        (_HIST_CLEARED_OLD, _HIST_CLEARED_NEW),
    ]:
        if patch(root, REL_HIST, old, new, required=False): changed = True

    # Step 3b: заменить строку внутри _on_context_menu при любом числе копий.
    hist_path = root / REL_HIST
    if hist_path.exists():
        text = hist_path.read_text(encoding="utf-8")
        old_line = 'action_compare = menu.addAction("Сравнить с текущим прогоном…")'
        new_line = 'action_compare = menu.addAction(tr("history.ctx_compare"))'
        if old_line in text:
            text = text.replace(old_line, new_line)
            if not fix_utils.DRY_RUN:
                hist_path.write_text(text, encoding="utf-8", newline="\n")
            print(f"  [hist] replaced ctx_compare line")
            changed = True

    # Step 4: QuickCheckWindow
    for old, new in [
        (_QC_IMPORTS_OLD, _QC_IMPORTS_NEW),
        (_QC_TITLE_OLD, _QC_TITLE_NEW),
        (_QC_INPUT_OLD, _QC_INPUT_NEW),
        (_QC_CHECK_BTN_OLD, _QC_CHECK_BTN_NEW),
        (_QC_FROM_OLD, _QC_FROM_NEW),
        (_QC_COMBO_INIT_OLD, _QC_COMBO_INIT_NEW),
        (_QC_REFRESH_OLD, _QC_REFRESH_NEW),
        (_QC_NO_IOCS_OLD, _QC_NO_IOCS_NEW),
        (_QC_TYPE_HINT_OLD, _QC_TYPE_HINT_NEW),
        (_QC_WARN_TYPE_OLD, _QC_WARN_TYPE_NEW),
        (_QC_NO_PROV_OLD, _QC_NO_PROV_NEW),
        (_QC_QUERYING_OLD, _QC_QUERYING_NEW),
        (_QC_NO_RESULTS_OLD, _QC_NO_RESULTS_NEW),
        (_QC_DONE_OLD, _QC_DONE_NEW),
        (_QC_ERROR_OLD, _QC_ERROR_NEW),
    ]:
        if patch(root, REL_QC, old, new, required=False): changed = True

    # Step 5: verification
    if not fix_utils.DRY_RUN:
        for rel in (REL_RU, REL_EN):
            text = (root / rel).read_text(encoding="utf-8")
            if "quick_check.querying" not in text:
                raise FixError(f"{rel}: не удалось применить")
        tl_text = (root / REL_TL).read_text(encoding="utf-8")
        if "timeline.no_selection" not in tl_text:
            raise FixError(f"{REL_TL}: не удалось применить")
        hist_text = (root / REL_HIST).read_text(encoding="utf-8")
        if "history.ctx_compare" not in hist_text:
            raise FixError(f"{REL_HIST}: не удалось применить")
        qc_text = (root / REL_QC).read_text(encoding="utf-8")
        if "quick_check.querying" not in qc_text:
            raise FixError(f"{REL_QC}: не удалось применить")

    return changed
