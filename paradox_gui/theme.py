"""Тема оформления GUI: палитра + QSS.

Почему отдельный модуль: цвета и стили нужны всем виджетам, а править
их в одном месте удобнее, чем искать hex по файлам. Палитра — единственный
источник правды; QSS тянет значения из неё через .format().

=============================================================================
 КАК ДОБАВЛЯТЬ СТИЛИ НОВЫХ ВИДЖЕТОВ
=============================================================================
 Всё ниже — один QSS-блок. При появлении новых виджетов стили дописываются
 ПЕРЕД закрывающей тройной кавычкой, в соответствующий раздел (или новый
 раздел с заголовком /* --- ИмяВиджета --- */).

 ВАЖНО:
   1. Литеральные CSS-блоки { ... } пишутся как {{ ... }}, иначе
      .format() примет их за placeholder и упадёт с SyntaxError/KeyError.
   2. Подстановки из PALETTE/SEVERITY — одинарные: {bg}, {accent},
      {border}, {danger}, {text} и т.д.
   3. id-селектор (QPushButton#primary) работает через setObjectName("primary").
   4. Селектор по динамическому свойству:
          QFrame#tile[hasContra="true"] { ... }
      требует repolish после setProperty (см. drop_zone.py, summary_grid.py).
   5. Секции идут в порядке: базовые → меню → вкладки → контролы →
      таблицы → служебные → виджет-специфичные.
=============================================================================
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPen
from PySide6.QtWidgets import QApplication

# Значения выдернуты из HTML-прототипа, но без пиксельной точности —
# важна структура, а не оттенки. Меняется одна строка → меняется везде.
PALETTE = {
    "bg":           "#1e1e2e",  # основной фон
    "bg_light":     "#282a36",  # панели, карточки, меню
    "bg_lighter":   "#313342",  # поля ввода, подложка кнопок
    "bg_hover":     "#3d4050",  # hover на пунктах меню / строк таблицы
    "text":         "#e0e0e0",
    "text_muted":   "#a0a0b0",
    "accent":       "#5b8cff",
    "accent_hover": "#4a7ae0",
    "border":       "#3a3d4d",
    "danger":       "#ff5555",
    "danger_light": "#ff8888",
    "success":      "#50fa7b",
    "violet":       "#c792ea",
}

# Severity — ключи совпадают со строками severity в dict из run_pipeline.
# Пригодится в contradiction_card.py, summary_grid.py, findings_table.py.
SEVERITY = {
    "critical": "#ff5555",
    "high":     "#ffb86c",
    "medium":   "#f1fa8c",
    "low":      "#50fa7b",
    "info":     "#8be9fd",
}

# Моно-шрифт для полей типа rule, subject, values, MITRE.
MONO_FAMILY = "'Cascadia Code', 'Consolas', 'Courier New', monospace"
UI_FAMILY   = "'Segoe UI', system-ui, sans-serif"


_QSS_TEMPLATE = """
/* =========================================================================
   ГЛОБАЛЬНО
   ========================================================================= */
QWidget {{
    background-color: {bg};
    color: {text};
    font-family: {ui};
    font-size: 14px;
}}

/* Подписи не должны рисовать собственный прямоугольник поверх
   карточек: иначе на плитках и панелях видны тёмные плашки. */
QLabel {{ background: transparent; }}

QMainWindow, QDialog {{ background-color: {bg}; }}

QToolTip {{
    background-color: {bg_lighter};
    color: {text};
    border: 1px solid {border};
    border-radius: 4px;
    padding: 6px 8px;
}}

QGroupBox {{
    border: 1px solid {border};
    border-radius: 8px;
    margin-top: 16px;
    padding: 12px 12px 10px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {text_muted};
}}

QSplitter::handle {{ background: {border}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

/* =========================================================================
   МЕНЮ
   ========================================================================= */
QMenuBar {{
    background: transparent;
    border-bottom: 1px solid {border};
    padding: 2px 4px;
}}
QMenuBar::item {{
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
    color: {text_muted};
}}
QMenuBar::item:selected {{ background: {bg_lighter}; color: {text}; }}

QMenu {{
    background-color: {bg_light};
    border: 1px solid {border};
    padding: 4px 0;
}}
QMenu::item {{
    padding: 6px 24px 6px 20px;
    color: {text};
}}
QMenu::item:selected {{ background: {bg_hover}; }}
QMenu::item:disabled {{ color: {text_muted}; }}
QMenu::separator {{
    height: 1px;
    background: {border};
    margin: 4px 8px;
}}

/* =========================================================================
   ВКЛАДКИ
   ========================================================================= */
QTabWidget::pane {{
    border: none;
    border-top: 1px solid {border};
    background: {bg};
}}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent;
    color: {text_muted};
    padding: 8px 14px;
    margin-right: 2px;
    border: none;
    border-bottom: 2px solid transparent;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-size: 13px;
}}
QTabBar::tab:hover {{
    color: {text};
    background: {bg_light};
}}
QTabBar::tab:selected {{
    color: {text};
    background: {bg_light};
    border-bottom: 2px solid {accent};
}}
QTabBar::tab:disabled {{ color: {border}; }}

/* =========================================================================
   КНОПКИ
   ========================================================================= */
QPushButton {{
    background-color: {bg_lighter};
    border: 1px solid {border};
    color: {text};
    padding: 6px 14px;
    min-height: 26px;
    border-radius: 6px;
}}
QPushButton:hover {{
    background-color: {bg_hover};
    border-color: {text_muted};
}}
QPushButton:pressed {{ background-color: {bg_light}; }}
QPushButton:focus {{ border-color: {accent}; }}
QPushButton:disabled {{
    color: {text_muted};
    background-color: {bg_light};
    border-color: {border};
}}

QPushButton#primary {{
    background-color: {accent};
    border-color: {accent};
    color: #ffffff;
    font-weight: 600;
}}
QPushButton#primary:hover {{
    background-color: {accent_hover};
    border-color: {accent_hover};
}}
QPushButton#primary:pressed {{ background-color: #3f6bd0; }}
QPushButton#primary:disabled {{
    background-color: {bg_lighter};
    border-color: {border};
    color: {text_muted};
}}

QPushButton#danger {{
    background-color: {danger};
    border-color: {danger};
    color: #ffffff;
}}
QPushButton#danger:hover {{
    background-color: #e04a4a;
    border-color: #e04a4a;
}}
QPushButton#danger:pressed {{
    background-color: #c93f3f;
    border-color: #c93f3f;
}}
QPushButton#danger:disabled {{
    background-color: {bg_lighter};
    border-color: {border};
    color: {text_muted};
}}
QPushButton#dangerOutline {{
    background: transparent;
    border: 1px solid {danger};
    color: {danger};
}}
QPushButton#dangerOutline:hover {{
    background-color: rgba(255, 85, 85, 0.12);
    border-color: {danger};
}}
QPushButton#dangerOutline:disabled {{
    background: transparent;
    border-color: {border};
    color: {text_muted};
}}

QPushButton#secondary {{
    background: transparent;
    border-color: {border};
    color: {text};
}}
QPushButton#secondary:hover {{
    background-color: {bg_lighter};
    border-color: {text_muted};
}}

QPushButton:checked {{
    background-color: rgba(91, 140, 255, 0.16);
    border-color: {accent};
}}

QPushButton#iconButton {{
    padding: 2px 6px;
    min-width: 26px;
    min-height: 22px;
}}

/* =========================================================================
   ПОЛЯ ВВОДА
   ========================================================================= */
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 6px;
    color: {text};
    padding: 5px 9px;
    selection-background-color: {accent};
    selection-color: #ffffff;
}}
QLineEdit {{ placeholder-text-color: {text_muted}; }}
QPlainTextEdit {{ placeholder-text-color: {text_muted}; }}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover,
QDoubleSpinBox:hover {{ border-color: {bg_hover}; }}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus,
QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {accent};
}}
QLineEdit:disabled, QPlainTextEdit:disabled, QTextEdit:disabled,
QComboBox:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled {{
    color: {text_muted};
    background-color: {bg_light};
    border-color: {border};
}}
QLineEdit[invalid="true"], QPlainTextEdit[invalid="true"],
QTextEdit[invalid="true"], QComboBox[invalid="true"],
QSpinBox[invalid="true"], QDoubleSpinBox[invalid="true"] {{
    border: 1px solid {danger};
}}
QLineEdit[modified="true"], QPlainTextEdit[modified="true"],
QTextEdit[modified="true"], QComboBox[modified="true"],
QSpinBox[modified="true"], QDoubleSpinBox[modified="true"] {{
    color: {high};
}}
QLineEdit[searchHit="true"], QPlainTextEdit[searchHit="true"],
QComboBox[searchHit="true"], QSpinBox[searchHit="true"],
QDoubleSpinBox[searchHit="true"] {{
    background-color: rgba(241, 250, 140, 0.10);
}}
QComboBox {{ padding-right: 22px; }}
QComboBox#filterType {{ min-width: 160px; max-width: 160px; }}
QComboBox#filterConf {{ min-width: 100px; max-width: 100px; }}
QComboBox#formatCombo {{ min-width: 250px; max-width: 250px; }}
QComboBox#typeCombo {{ min-width: 110px; max-width: 110px; }}
QComboBox#comboWide {{ min-width: 420px; }}
QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 22px;
    border: none;
}}
/* Стрелку рисуем PNG-шевроном: QSS не умеет треугольники из рамок,
   а внешних SVG/PNG в пакете нет — файл создаётся в temp при старте. */
QComboBox::down-arrow {{
    image: {arrow_down};
    width: 9px;
    height: 6px;
}}
QComboBox::down-arrow:disabled {{
    image: {arrow_down_disabled};
    width: 9px;
    height: 6px;
}}
QComboBox QAbstractItemView {{
    background: {bg_light};
    border: 1px solid {border};
    padding: 4px;
    outline: none;
    selection-background-color: {bg_hover};
    selection-color: {text};
}}
QComboBox QAbstractItemView::item {{
    padding: 5px 8px;
    border-radius: 4px;
}}

QSpinBox, QDoubleSpinBox {{ padding-right: 22px; }}
QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 18px;
    background: {bg_lighter};
    border-left: 1px solid {border};
    border-bottom: 1px solid {border};
    border-top-right-radius: 5px;
}}
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 18px;
    background: {bg_lighter};
    border-left: 1px solid {border};
    border-bottom-right-radius: 5px;
}}
QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background: {bg_hover};
}}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    image: {arrow_up};
    width: 7px;
    height: 5px;
}}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    image: {arrow_down};
    width: 7px;
    height: 5px;
}}

QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {border};
    border-radius: 3px;
    background: {bg};
}}
QCheckBox::indicator:checked {{
    background: {accent};
    border-color: {accent};
}}

QRadioButton {{ spacing: 8px; }}
QRadioButton::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {border};
    border-radius: 8px;
    background: {bg};
}}
QRadioButton::indicator:checked {{
    background: {accent};
    border: 4px solid {bg_lighter};
}}
QCheckBox:disabled, QRadioButton:disabled {{ color: {text_muted}; }}

QToolButton {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 4px 8px;
    color: {text_muted};
}}
QToolButton:hover {{
    background: {bg_lighter};
    border-color: {border};
    color: {text};
}}
QToolButton:pressed {{ background: {bg_light}; }}
QToolButton:disabled {{ color: {text_muted}; }}

QSlider {{ min-height: 20px; }}
QSlider::groove:horizontal {{
    height: 4px;
    background: {bg_lighter};
    border-radius: 2px;
}}
QSlider::sub-page:horizontal {{
    background: {accent};
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    width: 12px;
    margin: -5px 0;
    border-radius: 6px;
    background: {text_muted};
}}
QSlider::handle:horizontal:hover {{ background: {accent}; }}
QSlider::groove:vertical {{
    width: 4px;
    background: {bg_lighter};
    border-radius: 2px;
}}
QSlider::add-page:vertical {{
    background: {accent};
    border-radius: 2px;
}}
QSlider::handle:vertical {{
    height: 12px;
    margin: 0 -5px;
    border-radius: 6px;
    background: {text_muted};
}}
QSlider::handle:vertical:hover {{ background: {accent}; }}

/* =========================================================================
   ТАБЛИЦЫ
   ========================================================================= */
QTableWidget, QTableView, QTreeWidget, QTreeView {{
    background-color: {bg_light};
    border: 1px solid {border};
    gridline-color: {border};
    selection-background-color: {bg_hover};
    alternate-background-color: {bg};
}}
QTreeWidget::item, QTreeView::item {{
    padding: 4px 6px;
    color: {text};
}}
QTreeWidget::item:selected, QTreeView::item:selected {{
    background: {bg_hover};
    color: {text};
}}
QTreeView::branch {{
    background: transparent;
}}
QHeaderView {{
    background-color: {bg_light};
}}
QHeaderView::section {{
    background-color: {bg_light};
    color: {text_muted};
    padding: 8px 10px;
    border: none;
    border-bottom: 1px solid {border};
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.04em;
}}
QHeaderView::section:vertical {{
    padding: 4px 8px;
    border-right: 1px solid {border};
    color: {text_muted};
    font-weight: 400;
}}
QTableWidget::item {{ padding: 6px 10px; }}
QTableWidget::item:hover {{ background: {bg_lighter}; }}
QTableWidget::item:selected {{
    background: rgba(91, 140, 255, 0.20);
    color: {text};
}}
QTableWidget QWidget#qt_scrollarea_viewport,
QTreeWidget QWidget#qt_scrollarea_viewport,
QTreeView QWidget#qt_scrollarea_viewport {{
    background-color: {bg_light};
}}
QTableWidget QScrollBar:vertical,
QTreeWidget QScrollBar:vertical,
QTreeView QScrollBar:vertical {{
    background: {bg_light};
}}
QTableWidget QScrollBar::add-page:vertical,
QTableWidget QScrollBar::sub-page:vertical,
QTreeWidget QScrollBar::add-page:vertical,
QTreeWidget QScrollBar::sub-page:vertical,
QTreeView QScrollBar::add-page:vertical,
QTreeView QScrollBar::sub-page:vertical {{
    background: {bg_light};
}}
QTableWidget QScrollBar::groove:vertical,
QTreeWidget QScrollBar::groove:vertical,
QTreeView QScrollBar::groove:vertical {{
    background: {bg_light};
}}
QTableCornerButton::section {{
    background-color: {bg_light};
    border: none;
    border-bottom: 1px solid {border};
}}

QListWidget {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px;
    outline: none;
    selection-background-color: {bg_hover};
    selection-color: {text};
}}
QListWidget::item {{
    padding: 6px 10px;
    border-radius: 4px;
    color: {text};
}}
QListWidget::item:hover {{ background: {bg_lighter}; }}
QListWidget::item:selected {{ background: {bg_hover}; color: {text}; }}

QDialogButtonBox {{ spacing: 8px; }}
QDialogButtonBox QPushButton {{ min-width: 84px; }}

/* =========================================================================
   ПРОГРЕСС-БАР / СТАТУС-БАР / СКРОЛЛБАРЫ
   ========================================================================= */
QProgressBar {{
    background-color: {bg_lighter};
    border: none;
    border-radius: 4px;
    min-height: 8px;
    max-height: 8px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {accent};
    border-radius: 4px;
}}

QStatusBar {{
    background-color: {bg_light};
    border-top: 1px solid {border};
    color: {text_muted};
    font-size: 12px;
}}
QStatusBar::item {{ border: none; }}
QStatusBar QLabel {{ padding: 2px 6px; }}

QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: #464a5c;
    border-radius: 4px;
    min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{ background: {accent}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: #464a5c;
    border-radius: 4px;
    min-width: 28px;
}}
QScrollBar::handle:horizontal:hover {{ background: {accent}; }}

/* =========================================================================
   СЛУЖЕБНЫЕ КЛАССЫ (setObjectName)
   ========================================================================= */
QFrame#cardContraCritical {{ border-left: 4px solid {critical}; }}
QFrame#cardContraHigh     {{ border-left: 4px solid {high}; }}
QFrame#cardContraMedium   {{ border-left: 4px solid {medium}; }}
QFrame#cardContraLow      {{ border-left: 4px solid {low}; }}

/* =========================================================================
   ВИДЖЕТ: DropZone
   ========================================================================= */


QFrame#dropZone {{
    border: 2px dashed {border};
    border-radius: 8px;
    background: transparent;
}}
QFrame#dropZone:hover {{
    border-color: {accent};
    background: rgba(91, 140, 255, 0.05);
}}
QFrame#dropZone[dragActive="true"] {{
    border-color: {accent};
    background: rgba(91, 140, 255, 0.10);
}}

QFrame#dropZone[compact="true"] {{
    border: 1px solid {border};
    border-radius: 6px;
    background: transparent;
}}
QFrame#dropZone[compact="true"]:hover {{
    border-color: {accent};
    background: rgba(91, 140, 255, 0.05);
}}
QFrame#dropZone[compact="true"][dragActive="true"] {{
    border-color: {accent};
    background: rgba(91, 140, 255, 0.10);
}}

/* =========================================================================
   ВИДЖЕТ: SummaryGrid
   ========================================================================= */
QFrame#summaryTile {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 8px;
}}
QFrame#summaryTile[hasContra="true"] {{
    border: 1px solid rgba(255, 85, 85, 0.5);
}}
QFrame#summaryTile:hover {{
    border-color: #4a4d5e;
}}
QLabel#summaryValue {{
    font-size: 22px;
    font-weight: 700;
    color: {accent};
}}
QLabel#summaryValue[empty="true"] {{
    color: {text_muted};
    font-weight: 500;
}}
QLabel#summaryValueContra {{
    font-size: 22px;
    font-weight: 700;
    color: {text};
}}
QLabel#summaryValueContra[empty="true"] {{
    color: {text_muted};
    font-weight: 500;
}}
QLabel#summaryValueContra[hasContra="true"] {{
    color: {danger};
}}

/* =========================================================================
   ВИДЖЕТ: панели и карточки (Observations / Highlights / экспорт)
   ========================================================================= */
QFrame#obsPanel, QFrame#highPanel, QFrame#card {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 10px;
}}
QFrame#obsPanel QFrame {{
    background: transparent;
    border: none;
}}
QLabel#panelTitle {{
    font-size: 12px;
    font-weight: 600;
    color: {text_muted};
    letter-spacing: 0.05em;
}}
QLabel#metricLabel {{
    color: {text_muted};
    font-size: 12px;
    font-weight: 600;
    min-width: 64px;
}}
QLabel#metricValue {{
    color: {text};
    font-size: 13px;
}}
QLabel#metricValue[empty="true"] {{ color: {text_muted}; }}

/* Точки категорий: те же цвета, что у полос карточек highlights. */
QLabel#metricDot {{ border-radius: 3px; }}
QLabel#metricDot[kind="http"]   {{ background-color: {accent}; }}
QLabel#metricDot[kind="dns"]    {{ background-color: {info}; }}
QLabel#metricDot[kind="flow"]   {{ background-color: {high}; }}
QLabel#metricDot[kind="hosts"]  {{ background-color: {success}; }}
QLabel#metricDot[kind="tcp"]    {{ background-color: {medium}; }}
QLabel#metricDot[kind="carved"] {{ background-color: {violet}; }}
QLabel#panelBody {{
    color: {text};
    font-size: 13px;
}}
QLabel#panelCount {{
    color: {text_muted};
    background-color: {bg_lighter};
    border-radius: 8px;
    padding: 0 7px;
    font-size: 11px;
    font-weight: 600;
}}

/* Highlights: цвет полосы и бейджа задаёт динамическое свойство kind. */
QFrame#highlightCard {{
    background-color: {bg};
    border: 1px solid {border};
    border-left: 3px solid {accent};
    border-radius: 8px;
}}
QFrame#highlightCard[kind="flow"] {{ border-left-color: {info}; }}
QFrame#highlightCard[kind="ext"]  {{ border-left-color: {high}; }}
QFrame#highlightCard:hover {{
    background-color: {bg_lighter};
    border-top-color: #4a4d5e;
    border-right-color: #4a4d5e;
    border-bottom-color: #4a4d5e;
}}

QLabel#highlightBadge {{
    color: {accent};
    background-color: rgba(91, 140, 255, 0.14);
    border-radius: 4px;
    padding: 2px 0;
    min-width: 46px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.08em;
}}
QLabel#highlightBadge[kind="flow"] {{
    color: {info};
    background-color: rgba(139, 233, 253, 0.12);
}}
QLabel#highlightBadge[kind="ext"] {{
    color: {high};
    background-color: rgba(255, 184, 108, 0.14);
}}
QLabel#highlightPrimary {{
    font-family: {mono};
    font-size: 12px;
    font-weight: 600;
    color: {text};
}}
QLabel#highlightSecondary {{
    font-size: 11px;
    color: {text_muted};
}}
QLabel#highlightMetric {{
    font-family: {mono};
    font-size: 11px;
    color: {text_muted};
}}
QLabel#highlightEmpty {{
    color: {text_muted};
    font-size: 12px;
    font-style: italic;
    padding: 2px 0;
}}
QPushButton#filterChip {{
    background: transparent;
    border: 1px solid {border};
    border-radius: 10px;
    padding: 2px 10px;
    min-height: 20px;
    font-size: 11px;
    color: {text_muted};
}}
QPushButton#filterChip:hover {{
    color: {text};
    border-color: {text_muted};
}}
QPushButton#filterChip:checked {{
    color: {text};
    background-color: rgba(91, 140, 255, 0.16);
    border-color: {accent};
}}
QPushButton#filterChip:checked:hover {{
    background-color: rgba(91, 140, 255, 0.22);
}}

QLabel#pageTitle {{
    font-size: 18px;
    font-weight: 600;
    color: {text};
}}
QTextBrowser#exportPreview {{
    background: {bg};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 10px 12px;
    font-family: {mono};
    font-size: 12px;
}}

/* =========================================================================
   ОБЩИЕ ТЕКСТОВЫЕ РОЛИ
   ========================================================================= */
QLabel#mono {{
    font-family: {mono};
    font-size: 12px;
}}
QLabel#dialogTitle {{
    font-size: 18px;
    font-weight: 600;
    color: {text};
}}
QLabel#sectionTitle {{
    font-size: 14px;
    font-weight: 600;
    color: {text};
}}
QLabel#sectionLabel {{
    font-size: 12px;
    font-weight: 600;
    color: {text_muted};
    letter-spacing: 0.04em;
    margin-top: 8px;
}}
QLabel#fieldLabel {{
    color: {text_muted};
    font-size: 12px;
    font-weight: 600;
}}
QLabel#hint {{
    color: {text_muted};
    font-size: 11px;
}}
QLabel#hintDanger {{
    color: {danger};
    font-size: 11px;
}}
QLabel#hint[level="error"] {{ color: {danger}; }}
QLabel#statusLine {{ color: {text_muted}; }}
QLabel#statusLine[level="warn"] {{ color: {high}; }}
QLabel#statusLine[level="error"] {{ color: {danger}; }}
QLineEdit#searchField {{ min-width: 240px; }}
QPlainTextEdit#listField {{ min-height: 60px; }}
/* Код инжекта: только текст, крупный моно-шрифт, без переносов. */
QPlainTextEdit#payloadViewer {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 8px 10px;
    font-family: {mono};
    font-size: 12px;
    color: {text};
}}
QListWidget#payloadList::item {{ padding: 6px 8px; }}
QComboBox#payloadVariant {{ min-width: 170px; }}
/* Статический предпросмотр payload'а: только разметка, без скриптов. */
QTextBrowser#payloadPreview {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 8px 12px;
    color: {text};
}}
QLabel#statusVersion {{
    color: {text_muted};
    padding: 0 8px;
}}
QLabel#aboutTitle {{
    font-size: 20px;
    font-weight: 700;
    color: {accent};
}}
QLabel#timeLabel {{
    color: {accent};
    font-family: {mono};
    font-weight: 600;
}}
QLabel#graphLegend {{
    color: {text_muted};
    font-size: 11px;
    margin-top: 10px;
}}
QLabel#warnText {{
    color: {danger};
    font-size: 13px;
}}
QLabel#providerName {{
    font-size: 12px;
    font-weight: 600;
}}
QLabel#providerSummary {{
    color: {text_muted};
    font-size: 12px;
}}
QLabel#verdict {{
    font-size: 11px;
    font-weight: 600;
}}
QLabel#verdict[verdict="bad"]   {{ color: {danger}; }}
QLabel#verdict[verdict="warn"]  {{ color: {high}; }}
QLabel#verdict[verdict="info"]  {{ color: {info}; }}
QLabel#verdict[verdict="clean"] {{ color: {success}; }}
QLabel#verdict[verdict="error"] {{ color: {danger}; }}
QLabel#verdict[verdict="empty"] {{ color: {text_muted}; }}
QLabel#emptyState {{
    color: {text_muted};
    font-size: 12px;
    font-style: italic;
    padding: 12px 4px;
}}
QLabel#emptyStateHint {{
    color: {text_muted};
    font-size: 12px;
}}
QLabel#dropIcon {{ font-size: 32px; }}
QLabel#dropTitle {{
    font-size: 15px;
    font-weight: 600;
}}
QLabel#dropHint {{ color: {text_muted}; }}

/* =========================================================================
   ОБЩИЕ КОНТЕЙНЕРЫ
   ========================================================================= */
QFrame#providerCard {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 10px;
}}
QFrame#providerCard QTextEdit {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 4px;
    font-family: {mono};
    font-size: 12px;
}}
QFrame#detailPanel {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 8px;
}}
QFrame#warnBanner {{
    background-color: rgba(255, 85, 85, 0.10);
    border: 1px solid {danger};
    border-radius: 8px;
}}
QFrame#hline {{
    background-color: {border};
    border: none;
    max-height: 1px;
}}
QWidget#topbar {{
    background-color: {bg_light};
    border-bottom: 1px solid {border};
}}
QFrame#card QTabBar::tab:selected {{
    background: {bg_lighter};
}}
QFrame#card QTabWidget::pane {{
    padding: 8px;
}}

QTextBrowser#graphInfo, QTextBrowser#storyBrowser {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 8px 12px;
    color: {text};
}}
QTextBrowser#roadmapBrowser {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 16px 20px;
    color: {text};
}}
QGraphicsView {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 8px;
}}

/* =========================================================================
   >>> СЛЕДУЮЩИЙ ВИДЖЕТ ДОБАВЛЯТЬ СЮДА <<<
   ========================================================================= */

   /* =========================================================================
   ВИДЖЕТ: HistoryView
   ========================================================================= */
QListWidget#historyList {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 4px;
    min-width: 320px;
    max-width: 320px;
    outline: none;
}}
QListWidget#historyList::item {{
    padding: 8px 10px;
    border-radius: 4px;
    color: {text};
}}
QListWidget#historyList::item:hover {{
    background: {bg_lighter};
}}
QListWidget#historyList::item:selected {{
    background: {bg_hover};
    color: {accent};
}}

QTextBrowser#historyDetails {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 8px 12px;
    color: {text};
    selection-background-color: {accent};
}}

   /* =========================================================================
   ВИДЖЕТ: SettingsView
   ========================================================================= */
QListWidget#settingsSidebar {{
    background-color: {bg_light};
    border: none;
    border-right: 1px solid {border};
    padding: 8px 4px;
    outline: none;
}}
QListWidget#settingsSidebar::item {{
    padding: 8px 12px;
    border-radius: 4px;
    color: {text_muted};
}}
QListWidget#settingsSidebar::item:hover {{
    background: {bg_lighter};
    color: {text};
}}
QListWidget#settingsSidebar::item:selected {{
    background: {accent};
    color: #ffffff;
}}

/* =========================================================================
   ВИДЖЕТ: Toast
   ========================================================================= */
QWidget#toast {{
    background-color: {bg_lighter};
    border: 1px solid {border};
    border-left: 4px solid {border};
    border-radius: 6px;
}}
QWidget#toast[kind="info"]    {{ border-left-color: {accent}; }}
QWidget#toast[kind="success"] {{ border-left-color: {success}; }}
QWidget#toast[kind="warn"]    {{ border-left-color: {medium}; }}
QWidget#toast[kind="error"]   {{ border-left-color: {danger}; }}

QLabel#toastText {{
    color: {text};
    font-size: 13px;
}}

/* =========================================================================
   ВИДЖЕТ: FindingsTable / FindingDialog
   ========================================================================= */
/* Таблица использует общий стиль QTableWidget — специфика только в
   компактности внутри секции. */
QFrame#card QTableWidget {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 4px;
}}
QFrame#card QTableWidget::item {{
    padding: 4px 8px;
}}

/* =========================================================================
   ВИДЖЕТ: ContradictionsSection
   ========================================================================= */
/* Секция использует общий QFrame#card — стили уже есть выше. */
QScrollArea {{
    background: transparent;
    border: none;
}}
QScrollArea > QWidget > QWidget {{
    background: transparent;
}}


   /* =========================================================================
   ВИДЖЕТ: ContradictionCard
   ========================================================================= */
QFrame#cardContraCritical,
QFrame#cardContraHigh,
QFrame#cardContraMedium,
QFrame#cardContraLow {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 0 10px 10px 0;
}}
QFrame#cardContraCritical {{ border-left: 4px solid {critical}; }}
QFrame#cardContraHigh     {{ border-left: 4px solid {high}; }}
QFrame#cardContraMedium   {{ border-left: 4px solid {medium}; }}
QFrame#cardContraLow      {{ border-left: 4px solid {low}; }}

QLabel#severityBadge_critical {{
    background: rgba(255, 85, 85, 0.2);
    color: {critical};
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
}}
QLabel#severityBadge_high {{
    background: rgba(255, 184, 108, 0.2);
    color: {high};
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
}}
QLabel#severityBadge_medium {{
    background: rgba(241, 250, 140, 0.2);
    color: {medium};
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
}}
QLabel#severityBadge_low {{
    background: rgba(80, 250, 123, 0.2);
    color: {low};
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
}}

QLabel#contraHint {{
    color: {text_muted};
    font-size: 12px;
    padding-left: 4px;
}}
QLabel#contraRule {{
    font-family: {mono};
    font-size: 12px;
    font-weight: 600;
}}
QLabel#contraSubject {{
    font-family: {mono};
    font-size: 12px;
    color: {accent};
}}
QFrame#contraFacts {{
    background-color: {bg_light};
    border-radius: 4px;
}}
QFrame#contraFacts QLabel {{
    color: {text_muted};
    font-size: 11px;
}}
QPushButton#small {{
    padding: 2px 9px;
    min-height: 20px;
    font-size: 12px;
}}

/* =========================================================================
   ВИДЖЕТ: RoadmapView + общие h1 / muted
   ========================================================================= */
/* QLabel#h1 и QLabel#muted уже используются в SettingsView и RunView,
   но глобального правила не было — цвет брался дефолтный. Вводим. */
QLabel#h1 {{
    font-size: 20px;
    font-weight: 600;
    color: {text};
}}
QLabel#subtitle {{
    color: {text_muted};
    font-size: 13px;
}}
QLabel#muted {{
    color: {text_muted};
}}

/* QTextBrowser наследует стиль QTextEdit, но как страница-документ
   не должен выглядеть как поле ввода: убираем рамку и паддинги. */
QTextBrowser {{
    background-color: {bg_light};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 8px 12px;
    color: {text};
    selection-background-color: {accent};
}}


"""


def _url(path: Path | str | None) -> str:
    return f'url("{Path(path).as_posix()}")' if path else "none"


def build_qss(
    arrow_down: Path | str | None = None,
    arrow_up: Path | str | None = None,
    arrow_down_disabled: Path | str | None = None,
) -> str:
    """Собрать QSS. Пути к стрелкам подставляются при старте приложения."""
    return _QSS_TEMPLATE.format(
        arrow_down=_url(arrow_down),
        arrow_up=_url(arrow_up),
        arrow_down_disabled=_url(arrow_down_disabled or arrow_down),
        ui=UI_FAMILY,
        mono=MONO_FAMILY,
        critical=SEVERITY["critical"],
        high=SEVERITY["high"],
        medium=SEVERITY["medium"],
        low=SEVERITY["low"],
        info=SEVERITY["info"],
        **PALETTE,
    )


#: QSS без сгенерированных стрелок — для тестов и как fallback.
QSS = build_qss()


def _chevron_png(path: Path, up: bool, color: str) -> None:
    """Нарисовать шеврон 2x: QSS уменьшает его до 9x6 (7x5 в спинбоксе)."""
    image = QImage(18, 12, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), 2.6)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    if up:
        painter.drawLine(4, 8, 9, 4)
        painter.drawLine(9, 4, 14, 8)
    else:
        painter.drawLine(4, 4, 9, 8)
        painter.drawLine(9, 8, 14, 4)
    painter.end()
    image.save(str(path), "PNG")


def _arrow_assets() -> dict[str, str]:
    """PNG-шевроны в temp: QSS не рисует треугольники без картинки."""
    directory = Path(tempfile.gettempdir()) / "paradox_theme"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        down_path = directory / "chevron-down-v1.png"
        up_path = directory / "chevron-up-v1.png"
        disabled_path = directory / "chevron-down-disabled-v2.png"
        if not down_path.exists():
            _chevron_png(down_path, up=False, color=PALETTE["text_muted"])
        if not up_path.exists():
            _chevron_png(up_path, up=True, color=PALETTE["text_muted"])
        if not disabled_path.exists():
            _chevron_png(
                disabled_path, up=False, color=PALETTE["text_muted"]
            )
    except OSError:
        return {}
    return {
        "arrow_down": str(down_path),
        "arrow_up": str(up_path),
        "arrow_down_disabled": str(disabled_path),
    }


def apply_theme(app: QApplication) -> None:
    """Накладывает QSS на QApplication. Вызывать один раз при старте."""
    app.setStyleSheet(build_qss(**_arrow_assets()))
