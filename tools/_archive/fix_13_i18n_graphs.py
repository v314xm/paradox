# tools/fix_13_i18n_graphs.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "13-i18n-graphs"
TITLE = "i18n: перевод GraphDialog, AttackGraphDialog и HostStory"
REL_RU = "paradox_gui/i18n/_ru.py"
REL_EN = "paradox_gui/i18n/_en.py"
REL_GRAPH = "paradox_gui/dialogs/graph_dialog.py"
REL_ATK = "paradox_gui/dialogs/attack_graph_dialog.py"
REL_STORY = "paradox_gui/dialogs/host_story_dialog.py"

_RU_OLD = '''    "contra.card_no_facts": "Фактов нет.",

}'''
_RU_NEW = '''    "contra.card_no_facts": "Фактов нет.",

    # --- Graph Dialogs ---
    "graph.title": "Граф связей (Pro)",
    "graph.only_findings": "Только сработки (Findings)",
    "graph.hide_isolated": "Скрыть изолированные узлы",
    "graph.time": "Время: —",
    "graph.tip": "Кликните на узел, чтобы увидеть хронологию.",
    "graph.legend_title": "<b>Легенда:</b>",
    "graph.legend_attacker": "Атакующий / Pivot",
    "graph.legend_victim": "Жертва",
    "graph.legend_internal": "Внутренний",
    "graph.legend_external": "Внешний",
    "graph.legend_subnet": "Подсеть / Другие",
    "graph.legend_finding": "Finding (Сработка)",
    "graph.reset": "Сброс",
    "graph.close": "Закрыть",

    "atk.title": "Граф атаки",
    "atk.paths": "Пути атаки ({count})",
    "atk.legend": "<b>Легенда:</b>",
    "atk.legend_entry": "Вход / Жертва",
    "atk.legend_pivot": "Pivot (Скомпрометирован)",
    "atk.legend_impact": "Impact / C2 (Цель)",
    "atk.legend_lines": "Линии: цвет = фаза kill-chain",
    "atk.legend_zoom": "Колесико мыши — масштаб | Зажать ЛКМ — перемещение",
    "atk.play": "Воспроизвести",
    "atk.pause": "Пауза",
    "atk.details": "Детали пути",
    "atk.export": "<b>Экспорт:</b>",
    "atk.close": "Закрыть",
    "atk.empty": "Нет данных об атаке — findings не образовали связей.",

    "story.title": "История хоста: {ip}",
    "story.timeline": "Хронология для {ip}",
    "story.total": "Всего событий:",
    "story.findings": "Находок:",
    "story.flows": "Потоков:",
    "story.empty": "Событий для этого IP не найдено.",
    "story.close": "Закрыть",

}'''

_EN_OLD = '''    "contra.card_no_facts": "No facts.",

}'''
_EN_NEW = '''    "contra.card_no_facts": "No facts.",

    # --- Graph Dialogs ---
    "graph.title": "Topology Graph (Pro)",
    "graph.only_findings": "Only Findings",
    "graph.hide_isolated": "Hide isolated nodes",
    "graph.time": "Time: —",
    "graph.tip": "Click a node to see the timeline.",
    "graph.legend_title": "<b>Legend:</b>",
    "graph.legend_attacker": "Attacker / Pivot",
    "graph.legend_victim": "Victim",
    "graph.legend_internal": "Internal",
    "graph.legend_external": "External",
    "graph.legend_subnet": "Subnet / Other",
    "graph.legend_finding": "Finding",
    "graph.reset": "Reset",
    "graph.close": "Close",

    "atk.title": "Attack Graph",
    "atk.paths": "Attack paths ({count})",
    "atk.legend": "<b>Legend:</b>",
    "atk.legend_entry": "Entry / Victim",
    "atk.legend_pivot": "Pivot (Compromised)",
    "atk.legend_impact": "Impact / C2 (Target)",
    "atk.legend_lines": "Lines: color = kill-chain phase",
    "atk.legend_zoom": "Mouse wheel — zoom | Hold LMB — pan",
    "atk.play": "Play",
    "atk.pause": "Pause",
    "atk.details": "Path Details",
    "atk.export": "<b>Export:</b>",
    "atk.close": "Close",
    "atk.empty": "No attack data — findings did not form connections.",

    "story.title": "Host story: {ip}",
    "story.timeline": "Timeline for {ip}",
    "story.total": "Total events:",
    "story.findings": "Findings:",
    "story.flows": "Flows:",
    "story.empty": "No events found for this IP.",
    "story.close": "Close",

}'''

# --- GraphDialog ---
_GRAPH_TITLE_OLD = '''        self.setWindowTitle("Граф связей (Pro)")'''
_GRAPH_TITLE_NEW = '''        self.setWindowTitle(tr("graph.title"))'''

_GRAPH_FILTERS_OLD = '''        self.cb_only_findings = QCheckBox("Только сработки (Findings)")'''
_GRAPH_FILTERS_NEW = '''        self.cb_only_findings = QCheckBox(tr("graph.only_findings"))'''

_GRAPH_FILTERS2_OLD = '''        self.cb_hide_isolated = QCheckBox("Скрыть изолированные узлы")'''
_GRAPH_FILTERS2_NEW = '''        self.cb_hide_isolated = QCheckBox(tr("graph.hide_isolated"))'''

_GRAPH_TIME_OLD = '''        self.lbl_time = QLabel("Время: —")'''
_GRAPH_TIME_NEW = '''        self.lbl_time = QLabel(tr("graph.time"))'''

_GRAPH_TIP_OLD = '''        self.info_panel.setHtml("<p style='color:#888;'>Кликните на узел, чтобы увидеть хронологию.<br>Двойной клик — открыть История хоста.</p>")'''
_GRAPH_TIP_NEW = '''        self.info_panel.setHtml(f"<p style='color:#888;'>{tr('graph.tip')}<br>Двойной клик — открыть {tr('story.title', ip='...')}.</p>")'''

_GRAPH_LEGEND_OLD = '''        legend = QLabel(
            "<b>Легенда:</b><br>"
            "<span style='color:#ff4444;'>●</span> Атакующий / Pivot<br>"
            "<span style='color:#ffaa00;'>●</span> Жертва<br>"
            "<span style='color:#44aaff;'>●</span> Внутренний<br>"
            "<span style='color:#888888;'>●</span> Внешний<br>"
            "<span style='color:#555555;'>●</span> Подсеть / Другие<br>"
            "<span style='color:#ff4444;'>- - -</span> Finding (Сработка)<br>"
        )'''
_GRAPH_LEGEND_NEW = '''        legend = QLabel(
            f"{tr('graph.legend_title')}<br>"
            f"<span style='color:#ff4444;'>●</span> {tr('graph.legend_attacker')}<br>"
            f"<span style='color:#ffaa00;'>●</span> {tr('graph.legend_victim')}<br>"
            f"<span style='color:#44aaff;'>●</span> {tr('graph.legend_internal')}<br>"
            f"<span style='color:#888888;'>●</span> {tr('graph.legend_external')}<br>"
            f"<span style='color:#555555;'>●</span> {tr('graph.legend_subnet')}<br>"
            f"<span style='color:#ff4444;'>- - -</span> {tr('graph.legend_finding')}<br>"
        )'''

_GRAPH_BTNS_OLD = '''        btn_reset = QPushButton("Сброс")'''
_GRAPH_BTNS_NEW = '''        btn_reset = QPushButton(tr("graph.reset"))'''

_GRAPH_BTNS2_OLD = '''        btn_close = QPushButton("Закрыть")'''
_GRAPH_BTNS2_NEW = '''        btn_close = QPushButton(tr("graph.close"))'''

# --- AttackGraphDialog ---
_ATK_HEAD_OLD = '''from pathlib import Path

from PySide6.QtCore import Qt, QTimer'''
_ATK_HEAD_NEW = '''from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from paradox_gui.i18n import tr'''

_ATK_TITLE_OLD = '''        self.setWindowTitle("Граф атаки")'''
_ATK_TITLE_NEW = '''        self.setWindowTitle(tr("atk.title"))'''

_ATK_PATHS_OLD = '''        lbl = QLabel(f"Пути атаки ({len(self._paths)})")'''
_ATK_PATHS_NEW = '''        lbl = QLabel(tr("atk.paths", count=len(self._paths)))'''

_ATK_LEGEND_OLD = '''        legend_layout.addWidget(QLabel("<b>Легенда:</b>"))'''
_ATK_LEGEND_NEW = '''        legend_layout.addWidget(QLabel(tr("atk.legend")))'''

_ATK_LEGEND1_OLD = '''        legend_layout.addWidget(_lbl("#40c040", "Вход / Жертва"))
        legend_layout.addWidget(_lbl("#e0a040", "Pivot (Скомпрометирован)"))
        legend_layout.addWidget(_lbl("#e04040", "Impact / C2 (Цель)"))
        legend_layout.addSpacing(24)
        legend_layout.addWidget(QLabel("<span style='color:#a0a0b0;'>Линии: цвет = фаза kill-chain</span>"))
        legend_layout.addStretch(1)
        legend_layout.addWidget(QLabel("<i style='color:#808090; font-size:11px;'>Колесико мыши — масштаб | Зажать ЛКМ — перемещение</i>"))'''
_ATK_LEGEND1_NEW = '''        legend_layout.addWidget(_lbl("#40c040", tr("atk.legend_entry")))
        legend_layout.addWidget(_lbl("#e0a040", tr("atk.legend_pivot")))
        legend_layout.addWidget(_lbl("#e04040", tr("atk.legend_impact")))
        legend_layout.addSpacing(24)
        legend_layout.addWidget(QLabel(f"<span style='color:#a0a0b0;'>{tr('atk.legend_lines')}</span>"))
        legend_layout.addStretch(1)
        legend_layout.addWidget(QLabel(f"<i style='color:#808090; font-size:11px;'>{tr('atk.legend_zoom')}</i>"))'''

_ATK_PLAY_OLD = '''        self._btn_play = QPushButton("\\u25b6 \\u0412\\u043e\\u0441\\u043f\\u0440\\u043e\\u0438\\u0437\\u0432\\u0435\\u0441\\u0442\\u0438")'''
_ATK_PLAY_NEW = '''        self._btn_play = QPushButton(f"\\u25b6 {tr('atk.play')}")'''

_ATK_DETAILS_OLD = '''        r_lbl = QLabel("\\u0414\\u0435\\u0442\\u0430\\u043b\\u0438 \\u043f\\u0443\\u0442\\u0438")'''
_ATK_DETAILS_NEW = '''        r_lbl = QLabel(tr("atk.details"))'''

_ATK_EXPORT_OLD = '''        btn_row.addWidget(QLabel("<b>Экспорт:</b>"))'''
_ATK_EXPORT_NEW = '''        btn_row.addWidget(QLabel(tr("atk.export")))'''

_ATK_CLOSE_OLD = '''        btn = QPushButton("\\u0417\\u0430\\u043a\\u0440\\u044b\\u0442\\u044c")'''
_ATK_CLOSE_NEW = '''        btn = QPushButton(tr("atk.close"))'''

_ATK_EMPTY_OLD = '''            text = QGraphicsTextItem("Нет данных об атаке — findings не образовали связей.")'''
_ATK_EMPTY_NEW = '''            text = QGraphicsTextItem(tr("atk.empty"))'''

_ATK_TGL_PLAY_OLD = '''            self._btn_play.setText("▶ Воспроизвести")'''
_ATK_TGL_PLAY_NEW = '''            self._btn_play.setText(f"▶ {tr('atk.play')}")'''

_ATK_TGL_PAUSE_OLD = '''            self._btn_play.setText("⏸ Пауза")'''
_ATK_TGL_PAUSE_NEW = '''            self._btn_play.setText(f"⏸ {tr('atk.pause')}")'''

# --- HostStoryDialog ---
_STORY_IMPORTS_OLD = '''from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)'''
_STORY_IMPORTS_NEW = '''from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)
from paradox_gui.i18n import tr'''

_STORY_TITLE_OLD = '''        self.setWindowTitle(f"История хоста: {ip}")'''
_STORY_TITLE_NEW = '''        self.setWindowTitle(tr("story.title", ip=ip))'''

_STORY_HTML_OLD = '''        html = f"<h2>Хронология для {story.get('target_ip', '?')}</h2>"
        html += f"<p><b>Всего событий:</b> {summary.get('total_events', 0)} "
        html += f"| <b>Находок:</b> {summary.get('findings_count', 0)} "
        html += f"| <b>Потоков:</b> {summary.get('flows_count', 0)}</p><hr>"

        if not events:
            html += "<p style='color:#a0a0b0;'>Событий для этого IP не найдено.</p>"'''
_STORY_HTML_NEW = '''        html = f"<h2>{tr('story.timeline', ip=story.get('target_ip', '?'))}</h2>"
        html += f"<p><b>{tr('story.total')}</b> {summary.get('total_events', 0)} "
        html += f"| <b>{tr('story.findings')}</b> {summary.get('findings_count', 0)} "
        html += f"| <b>{tr('story.flows')}</b> {summary.get('flows_count', 0)}</p><hr>"

        if not events:
            html += f"<p style='color:#a0a0b0;'>{tr('story.empty')}</p>"'''

_STORY_CLOSE_OLD = '''        btn_close = QPushButton("Закрыть")'''
_STORY_CLOSE_NEW = '''        btn_close = QPushButton(tr("story.close"))'''


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_RU, _RU_OLD, _RU_NEW, required=False): changed = True
    if patch(root, REL_EN, _EN_OLD, _EN_NEW, required=False): changed = True

    for rel, pairs in [
        (REL_GRAPH, [
            (_GRAPH_TITLE_OLD, _GRAPH_TITLE_NEW),
            (_GRAPH_FILTERS_OLD, _GRAPH_FILTERS_NEW),
            (_GRAPH_FILTERS2_OLD, _GRAPH_FILTERS2_NEW),
            (_GRAPH_TIME_OLD, _GRAPH_TIME_NEW),
            (_GRAPH_TIP_OLD, _GRAPH_TIP_NEW),
            (_GRAPH_LEGEND_OLD, _GRAPH_LEGEND_NEW),
            (_GRAPH_BTNS_OLD, _GRAPH_BTNS_NEW),
            (_GRAPH_BTNS2_OLD, _GRAPH_BTNS2_NEW)
        ]),
        (REL_ATK, [
            (_ATK_HEAD_OLD, _ATK_HEAD_NEW),
            (_ATK_TITLE_OLD, _ATK_TITLE_NEW),
            (_ATK_PATHS_OLD, _ATK_PATHS_NEW),
            (_ATK_LEGEND_OLD, _ATK_LEGEND_NEW),
            (_ATK_LEGEND1_OLD, _ATK_LEGEND1_NEW),
            (_ATK_PLAY_OLD, _ATK_PLAY_NEW),
            (_ATK_DETAILS_OLD, _ATK_DETAILS_NEW),
            (_ATK_EXPORT_OLD, _ATK_EXPORT_NEW),
            (_ATK_CLOSE_OLD, _ATK_CLOSE_NEW),
            (_ATK_EMPTY_OLD, _ATK_EMPTY_NEW),
            (_ATK_TGL_PLAY_OLD, _ATK_TGL_PLAY_NEW, 2),  # <--- ВОТ ЗДЕСЬ count=2
            (_ATK_TGL_PAUSE_OLD, _ATK_TGL_PAUSE_NEW)
        ]),
        (REL_STORY, [
            (_STORY_IMPORTS_OLD, _STORY_IMPORTS_NEW),
            (_STORY_TITLE_OLD, _STORY_TITLE_NEW),
            (_STORY_HTML_OLD, _STORY_HTML_NEW),
            (_STORY_CLOSE_OLD, _STORY_CLOSE_NEW)
        ]),
    ]:
        for item in pairs:
            if len(item) == 2:
                old, new = item
                count = 1
            else:
                old, new, count = item
            if patch(root, rel, old, new, required=False, count=count): changed = True

    if not fix_utils.DRY_RUN:
        if "graph.title" not in (root / REL_RU).read_text(encoding="utf-8"):
            raise FixError(f"{REL_RU}: не удалось применить")

    return changed
