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


QSS = """
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
}}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover,
QDoubleSpinBox:hover {{ border-color: {bg_hover}; }}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus,
QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {accent};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {bg_light};
    border: 1px solid {border};
    selection-background-color: {bg_hover};
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
QTableWidget::item {{ padding: 6px 10px; }}
QTableWidget::item:hover {{ background: {bg_lighter}; }}
QTableWidget::item:selected {{
    background: rgba(91, 140, 255, 0.20);
    color: {text};
}}

/* =========================================================================
   ПРОГРЕСС-БАР / СТАТУС-БАР / СКРОЛЛБАРЫ
   ========================================================================= */
QProgressBar {{
    background-color: {bg_lighter};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {accent};
    border-radius: 3px;
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
QFrame#highlightCard:hover {{ background-color: {bg_lighter}; }}

QLabel#highlightBadge {{
    color: {accent};
    background-color: rgba(91, 140, 255, 0.14);
    border-radius: 4px;
    padding: 2px 0;
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
QWidget#toast_info,
QWidget#toast_success,
QWidget#toast_warn,
QWidget#toast_error {{
    background-color: {bg_lighter};
    border: 1px solid {border};
    border-radius: 6px;
}}
QWidget#toast_info    {{ border-left: 4px solid {accent}; }}
QWidget#toast_success {{ border-left: 4px solid {success}; }}
QWidget#toast_warn    {{ border-left: 4px solid {medium}; }}
QWidget#toast_error   {{ border-left: 4px solid {danger}; }}

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

QDialog QLabel#h1 {{
    font-size: 14px;
    font-weight: 600;
    color: {text_muted};
    margin-top: 6px;
}}
QDialog QLabel#mono {{
    font-family: {mono};
    font-size: 12px;
}}




/* =========================================================================
   ВИДЖЕТ: ContradictionDialog
   ========================================================================= */
QDialog QLabel#h1 {{
    font-size: 14px;
    font-weight: 600;
    color: {text_muted};
    margin-top: 6px;
}}
QDialog QFrame#contraFacts {{
    background-color: {bg};
    border: 1px solid {border};
    border-radius: 4px;
}}
QDialog QFrame#contraFacts QLabel {{
    color: {text_muted};
    font-size: 12px;
}}

/* =========================================================================
   ВИДЖЕТ: ContradictionsSection
   ========================================================================= */
/* Секция использует общий QFrame#card — стили уже есть выше.
   Специфичных правил нет, кроме скролла без рамки. */
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
    border-radius: 0 8px 8px 0;
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
QFrame#contraFacts {{
    background-color: {bg_light};
    border-radius: 4px;
}}
QFrame#contraFacts QLabel {{
    color: {text_muted};
    font-size: 11px;
}}
QPushButton#small {{
    padding: 3px 10px;
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


""".format(
    ui=UI_FAMILY,
    mono=MONO_FAMILY,
    critical=SEVERITY["critical"],
    high=SEVERITY["high"],
    medium=SEVERITY["medium"],
    low=SEVERITY["low"],
    info=SEVERITY["info"],
    **PALETTE,
)


def apply_theme(app: QApplication) -> None:
    """Накладывает QSS на QApplication. Вызывать один раз при старте."""
    app.setStyleSheet(QSS)
