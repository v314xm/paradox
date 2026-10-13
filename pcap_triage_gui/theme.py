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

QMainWindow, QDialog {{ background-color: {bg}; }}

/* =========================================================================
   МЕНЮ
   ========================================================================= */
QMenuBar {{
    background-color: {bg_light};
    border-bottom: 1px solid {border};
    padding: 0 4px;
}}
QMenuBar::item {{
    background: transparent;
    padding: 6px 12px;
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
    background: {bg};
}}
QTabBar::tab {{
    background: {bg_light};
    color: {text_muted};
    padding: 8px 18px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{ color: {text}; }}
QTabBar::tab:selected {{
    color: {accent};
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
    border-radius: 4px;
}}
QPushButton:hover {{ background-color: {bg_hover}; }}
QPushButton:disabled {{ color: {text_muted}; background-color: {bg_light}; }}

QPushButton#primary {{
    background-color: {accent};
    border-color: {accent};
    color: #ffffff;
}}
QPushButton#primary:hover {{ background-color: {accent_hover}; }}
QPushButton#primary:disabled {{ background-color: {bg_lighter}; color: {text_muted}; }}

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
    border-radius: 4px;
    color: {text};
    padding: 4px 8px;
    selection-background-color: {accent};
}}
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
QTableWidget, QTableView {{
    background-color: {bg_light};
    border: 1px solid {border};
    gridline-color: {border};
    selection-background-color: {bg_hover};
    alternate-background-color: {bg};
}}
QHeaderView::section {{
    background-color: {bg_lighter};
    color: {text_muted};
    padding: 6px 10px;
    border: none;
    border-bottom: 1px solid {border};
}}
QTableWidget::item {{ padding: 4px 8px; }}
QTableWidget::item:selected {{ background: {bg_hover}; }}

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
}}
QStatusBar::item {{ border: none; }}

QScrollBar:vertical {{
    background: {bg};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {bg_hover};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar:horizontal {{
    background: {bg};
    height: 10px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {bg_hover};
    border-radius: 5px;
    min-width: 24px;
}}

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
QLabel#summaryValue {{
    font-size: 22px;
    font-weight: 700;
    color: {accent};
}}
QLabel#summaryValueContra {{
    font-size: 22px;
    font-weight: 700;
    color: {text};
}}
QLabel#summaryValueContra[hasContra="true"] {{
    color: {danger};
}}

/* =========================================================================
   >>> СЛЕДУЮЩИЙ ВИДЖЕТ ДОБАВЛЯТЬ СЮДА <<<
   ========================================================================= */
   
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
    
   
""".format(
    ui=UI_FAMILY,
    mono=MONO_FAMILY,
    critical=SEVERITY["critical"],
    high=SEVERITY["high"],
    medium=SEVERITY["medium"],
    low=SEVERITY["low"],
    **PALETTE,
)


def apply_theme(app: QApplication) -> None:
    """Накладывает QSS на QApplication. Вызывать один раз при старте."""
    app.setStyleSheet(QSS)