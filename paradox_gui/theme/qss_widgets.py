"""QSS служебных классов и виджет-специфичных правил."""
from __future__ import annotations

QSS_WIDGETS = """\
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
QFrame#summaryTile:hover {{
    border-color: #4a4d5e;
}}
QFrame#summaryTile[hasContra="true"] {{
    border-color: rgba(255, 85, 85, 0.5);
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
QLabel#summaryValue[hasContra="true"] {{
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
QLabel#metricDot[kind="traffic"] {{ background-color: {high}; }}
QLabel#metricDot[kind="proto"]   {{ background-color: {accent}; }}
QLabel#metricDot[kind="tls"]     {{ background-color: {violet}; }}
QLabel#metricDot[kind="diag"]    {{ background-color: {text_muted}; }}
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
QFrame#highlightCard[kind="contra"]   {{ border-left-color: {critical}; }}
QFrame#highlightCard[kind="finding"]  {{ border-left-color: {high}; }}
QFrame#highlightCard[kind="upload"]   {{ border-left-color: {violet}; }}
QFrame#highlightCard[kind="download"] {{ border-left-color: {info}; }}
QFrame#highlightCard[kind="dns"]      {{ border-left-color: {medium}; }}
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
QLabel#highlightBadge[kind="contra"] {{
    color: {critical};
    background-color: rgba(255, 85, 85, 0.16);
}}
QLabel#highlightBadge[kind="finding"] {{
    color: {high};
    background-color: rgba(255, 184, 108, 0.14);
}}
QLabel#highlightBadge[kind="upload"] {{
    color: {violet};
    background-color: rgba(199, 146, 234, 0.14);
}}
QLabel#highlightBadge[kind="download"] {{
    color: {info};
    background-color: rgba(139, 233, 253, 0.12);
}}
QLabel#highlightBadge[kind="dns"] {{
    color: {medium};
    background-color: rgba(241, 250, 140, 0.12);
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
   ВИДЖЕТ: общие h1 / muted
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
