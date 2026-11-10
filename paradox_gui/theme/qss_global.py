"""Базовые QSS-правила: фон, меню, вкладки, кнопки, поля, таблицы, скроллы."""
from __future__ import annotations

QSS_GLOBAL = """
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

"""
