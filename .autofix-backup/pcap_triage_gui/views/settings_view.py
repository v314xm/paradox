"""Вкладка «Настройки» — 11 секций с сайдбаром.

Секции соответствуют Config ядра. Реализованы: Пороги, Детекторы,
Противоречия, Brute force, Сеть, Производительность, Allowlist, DGA,
Threat Intel, Отчёты. Заглушка — только «Общие».
"""
from pathlib import Path
import re

from pcap_triage_gui.settings_rehydrate import rehydrate
from pcap_triage_gui.profiles import (
    ALL_PROFILES,
    DEFAULT_PROFILE_KEY,
    get_profile,
)
from pcap_triage_gui.field_help import (
    SECTION_BY_TITLE,
    get_field_help,
    get_section_help,
)
from pcap_triage_gui.widgets.editable_list import (
    PORT_FIELDS,
    EditableListWidget,
)
from pcap_triage_gui.detector_help import get_detector_help
from pcap_triage_gui.contradiction_help import get_contradiction_help
from pcap_triage_gui.settings_store import SettingsStore
from pcap_triage_gui.secrets_store import SecretsStore

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


_SECTIONS = (
    ("general",       "Общие"),
    ("thresholds",    "Пороги"),
    ("detectors",     "Детекторы"),
    ("contradictions", "Противоречия"),
    ("allowlist",     "Allowlist"),
    ("dga",           "DGA"),
    ("brute",         "Brute force"),
    ("network",       "Сеть"),
    ("reports",       "Отчёты"),
    ("yara", "YARA"),
    ("threatintel",   "Threat Intel"),
    ("perf",          "Производительность"),
)

_DETECTORS = (
    ("dga",                "DGA — домены-генераторы"),
    ("port_scan",          "Port scan"),
    ("suspicious_port",    "Suspicious port"),
    ("nxdomain_burst",     "NXDOMAIN burst"),
    ("cloud_tunnel",       "Cloud tunnel"),
    ("ip_check_service",   "IP check service"),
    ("typosquatting",      "Typosquatting"),
    ("sni_mismatch",       "SNI mismatch"),
    ("ja3_malware",        "JA3 malware"),
    ("brute_force",        "Brute force (HTTP)"),
    ("ftp_brute_force",    "FTP brute force"),
    ("beaconing",          "Beaconing"),
    ("dns_tunneling",      "DNS tunneling"),
    ("lateral_movement",   "Lateral movement"),
    ("large_transfer",     "Large transfer"),
    ("vulnerable_path",    "Vulnerable path"),
    ("command_injection",  "Command injection"),
    ("ssh_brute_force", "SSH brute force"),
    ("smtp_spam", "SMTP spam"),
    ("yara", "YARA"),
)

# 12 правил из pcap_triage/contradictions/rules/.
# Ключ — имя класса; analysis_worker фильтрует по type(r).__name__.
_CONTRADICTIONS = (
    ("VictimMakesAttackRule",   "victim_makes_attack (PIVOT) — critical"),
    ("MacIpConflictRule",       "mac_ip_conflict (ARP-spoof) — critical"),
    ("SniHostMismatchRule",     "sni_host_mismatch (fronting) — high"),
    ("Ja3UaMismatchRule",       "ja3_ua_mismatch (UA spoof) — high"),
    ("ReverseAsymmetryRule",    "reverse_asymmetry (exfil) — medium"),
    ("PortServiceMismatchRule", "port_service_mismatch (tunnel) — high"),
    ("DirectIpNoDnsRule",       "direct_ip_no_dns (hardcoded) — medium"),
    # v0.9.0: добавлены недостающие 5 правил
    ("SniWithoutDnsRule",       "sni_without_dns (SNI без DNS) — high"),
    ("DnsAnswerMismatchRule",   "dns_answer_mismatch (подмена ответа) — critical"),
    ("SniCertMismatchRule",     "sni_cert_mismatch (CN/SAN ≠ SNI) — high"),
    ("SelfSignedCertRule",      "self_signed_cert — medium"),
    ("ExpiredCertRule",         "expired_cert — medium"),
)


# Описания секций, которые пока не реализованы.
# HTML, потому что QLabel умеет rich text из коробки.
_PLACEHOLDER_TEXT = {
    "general": (
        "<b>Что будет.</b> Общие настройки: <b>язык интерфейса</b> "
        "(русский / английский), путь к отчётам по умолчанию, "
        "поведение при старте (открывать последний pcap или пустую "
        "вкладку), тема оформления (сейчас тёмная — единственная)."
        "<br><br>"
        "<b>Почему пусто.</b> Сейчас эти значения либо захардкожены "
        "в GUI, либо не критичны. Появятся, когда появится вторая "
        "локализация или несколько профилей работы."
    ),
}


# =============================================================================
# Хелперы парсинга списков из текстовых полей
# =============================================================================

def _parse_ports(text: str) -> frozenset[int]:
    """'80, 443 8080 # web' → {80, 443, 8080}.

    Разделители — пробелы, запятые, переводы строк. Комментарии (после #)
    игнорируются. Невалидные токены пропускаются молча: GUI не должен
    падать из-за опечатки.
    """
    out: set[int] = set()
    for chunk in text.replace(",", " ").split():
        if chunk.startswith("#"):
            break
        try:
            p = int(chunk)
        except ValueError:
            continue
        if 1 <= p <= 65535:
            out.add(p)
    return frozenset(out)


def _parse_ports_with_report(text: str) -> tuple[frozenset[int], list[str]]:
    """Как _parse_ports, но возвращает список пропущенных токенов.

    Используется в _apply_* для счётчика «N пропущено».
    """
    out: set[int] = set()
    skipped: list[str] = []
    for chunk in text.replace(",", " ").split():
        if chunk.startswith("#"):
            break
        try:
            p = int(chunk)
        except ValueError:
            skipped.append(chunk)
            continue
        if 1 <= p <= 65535:
            out.add(p)
        else:
            skipped.append(chunk)
    return frozenset(out), skipped


def _format_ports(ports) -> str:
    """{443, 80} → '80, 443'. Сортировка — стабильный порядок в UI."""
    return ", ".join(str(p) for p in sorted(ports))


def _parse_lines(text: str) -> frozenset[str]:
    """Один элемент на строку. Пустые строки и # комментарии — пропуск."""
    return frozenset(
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def _format_lines(items) -> str:
    """frozenset[str] → многострочный текст, сортировка для стабильности."""
    return "\n".join(sorted(items))


class SettingsView(QWidget):
    # Дефолты до того, как __init__ успеет их поставить.
    _active_profile_key: str = DEFAULT_PROFILE_KEY
    _search_text: str = ""
    _defaults = None
    thresholds_applied = Signal(object)
    detectors_applied = Signal(object)
    contradictions_applied = Signal(object)
    # Секции Brute force / Сеть / Производительность / Allowlist / DGA /
    # Threat Intel / Отчёты шлют плоский dict {поле Config: значение}.
    # run_view мерджит в общий overrides.
    config_applied = Signal(object)

    def __init__(self, parent=None, store: SettingsStore | None = None) -> None:
        super().__init__(parent)
        self._store = store
        self._secrets = SecretsStore()
        self._active_profile_key = self._read_active_profile()
        self._build_ui()
        self._apply_help_tooltips()
        self.load_from_store()
        self._wire_modified_signals()
        self._check_modified()
        self._wire_modified_signals()
        self._check_modified()
        # Автосохранение при каждом Apply. Подписка на свои же сигналы:
        # не надо трогать _apply_* методы.
        self.thresholds_applied.connect(self._save_overrides)
        self.config_applied.connect(self._save_overrides)
        self.detectors_applied.connect(self._save_disabled_detectors)
        self.contradictions_applied.connect(self._save_disabled_contradictions)

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        search_row = QHBoxLayout()
        search_row.setContentsMargins(8, 8, 8, 4)
        search_row.setSpacing(6)

        self._search_line = QLineEdit()
        self._search_line.setPlaceholderText(
            "Поиск по настройкам (Ctrl+F)…"
        )
        self._search_line.setClearButtonEnabled(True)
        self._search_line.setToolTip(
            "Ищет по имени поля и по описанию (tooltip).\n"
            "Примеры:\n"
            "  beaconing  →  все поля детектора beaconing\n"
            "  энтроп     →  DGA: порог энтропии (совпадение в описании)\n"
            "  nxdomain   →  три поля NXDOMAIN burst\n"
            "\n"
            "Ctrl+F — фокус в поле. Esc — очистить."
        )
        self._search_line.textChanged.connect(self._apply_search)
        self._search_line.installEventFilter(self)
        search_row.addWidget(self._search_line, stretch=1)

        self._search_hint = QLabel("")
        self._search_hint.setObjectName("muted")
        search_row.addWidget(self._search_hint)

        outer.addLayout(search_row)

        # Ctrl+F — фокус в поиск. Стандартный жест, ожидаемый
        # пользователем. Работает, когда фокус внутри SettingsView.
        from PySide6.QtCore import Qt as _Qt
        from PySide6.QtGui import QKeySequence, QShortcut
        sc = QShortcut(QKeySequence("Ctrl+F"), self)
        sc.setContext(_Qt.ShortcutContext.WidgetWithChildrenShortcut)
        sc.activated.connect(self._focus_search)
        # Держим ссылку, чтобы шорткат не собрался GC.
        self._search_shortcut = sc

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._sidebar = self._build_sidebar()
        layout.addWidget(self._sidebar)

        self._stack = QStackedWidget()
        self._build_pages()
        layout.addWidget(self._stack, stretch=1)
        outer.addLayout(layout, stretch=1)

        # Статус-полоса: счётчик пропущенных токенов, короткие подсказки.
        self._status_label = QLabel("")
        self._status_label.setObjectName("muted")
        self._status_label.setContentsMargins(12, 4, 12, 4)
        outer.addWidget(self._status_label)

        self._sidebar.currentRowChanged.connect(self._stack.setCurrentIndex)
        self._sidebar.setCurrentRow(0)

    def _build_sidebar(self) -> QListWidget:
        w = QListWidget()
        w.setObjectName("settingsSidebar")
        w.setFixedWidth(200)
        for key, label in _SECTIONS:
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, key)
            w.addItem(item)
        return w

    def _build_pages(self) -> None:
        for key, label in _SECTIONS:
            if key == "thresholds":
                self._stack.addWidget(self._build_thresholds_page())
            elif key == "detectors":
                self._stack.addWidget(self._build_detectors_page())
            elif key == "contradictions":
                self._stack.addWidget(self._build_contradictions_page())
            elif key == "brute":
                self._stack.addWidget(self._build_brute_force_page())
            elif key == "network":
                self._stack.addWidget(self._build_network_page())
            elif key == "perf":
                self._stack.addWidget(self._build_performance_page())
            elif key == "allowlist":
                self._stack.addWidget(self._build_allowlist_page())
            elif key == "dga":
                self._stack.addWidget(self._build_dga_page())
            elif key == "yara":
                self._stack.addWidget(self._build_yara_page())
            elif key == "reports":
                self._stack.addWidget(self._build_reports_page())
            elif key == "yara":
                self._stack.addWidget(self._build_yara_page())
            elif key == "yara":
                self._stack.addWidget(self._build_yara_page())
            elif key == "threatintel":
                self._stack.addWidget(self._build_threatintel_page())
            elif key == "general":
                self._stack.addWidget(self._build_general_page())
            else:
                self._stack.addWidget(self._placeholder_page(key, label))

    def _placeholder_page(self, key: str, title: str) -> QWidget:
        """Заглушка секции с осмысленным описанием.

        Каждая заглушка объясняет, что здесь будет и зачем. Это лучше
        безликого «в разработке»: пользователь видит смысл.
        """
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(24, 24, 24, 24)
        v.setSpacing(12)

        h = QLabel(title)
        h.setObjectName("h1")
        v.addWidget(h)

        body = _PLACEHOLDER_TEXT.get(key, "Секция в разработке.")
        hint = QLabel(body)
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        hint.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(hint)
        v.addStretch(1)
        return w

    def _apply_help_tooltips(self) -> None:
        """Поставить tooltip'ы на поля и заголовки секций.

        Заголовки: tooltip вешается на QLabel из _make_header по
        карте SECTION_BY_TITLE. Поля: обход всех *_inputs-групп,
        tooltip из get_field_help.
        """
        for group_name in (
            "_threshold_inputs", "_brute_inputs", "_network_inputs",
            "_perf_inputs", "_allowlist_inputs", "_dga_inputs",
            "_reports_inputs", "_ti_inputs",
        ):
            group = getattr(self, group_name, None)
            if not isinstance(group, dict):
                continue
            for key, widget in group.items():
                if widget is None:
                    continue
                try:
                    widget.setToolTip(get_field_help(key))
                except Exception:
                    pass

    # =========================================================================
    # БЕЙДЖ «ИЗМЕНЕНО» И СТАТУС-ПОЛОСА
    # =========================================================================

    _MARK_STYLE = "color: #d0a060;"

    _INPUT_GROUPS = (
        "_threshold_inputs", "_brute_inputs", "_network_inputs",
        "_perf_inputs", "_allowlist_inputs", "_dga_inputs",
        "_reports_inputs", "_ti_inputs",
    )

    def _notify_status(self, msg: str, level: str = "info",
                       timeout_ms: int = 4000) -> None:
        label = getattr(self, "_status_label", None)
        if label is None:
            return
        color = {"warn": "#d0a060", "error": "#e06060"}.get(level, "")
        label.setStyleSheet(f"color: {color};" if color else "")
        label.setText(msg)

        from PySide6.QtCore import QTimer

        def _clear():
            try:
                label.setText("")
            except RuntimeError:
                pass

        QTimer.singleShot(timeout_ms, _clear)

    def _wire_modified_signals(self) -> None:
        for group_name in self._INPUT_GROUPS:
            group = getattr(self, group_name, None)
            if not isinstance(group, dict):
                continue
            for widget in group.values():
                if isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                    widget.valueChanged.connect(self._check_modified)
                elif isinstance(widget, QCheckBox):
                    widget.stateChanged.connect(self._check_modified)
                elif isinstance(widget, QLineEdit):
                    widget.textChanged.connect(self._check_modified)
                elif isinstance(widget, (QPlainTextEdit, EditableListWidget)):
                    widget.textChanged.connect(self._check_modified)

    def _check_modified(self, *args) -> None:
        try:
            from pcap_triage.config import Config
            self._defaults = Config()
        except ImportError:
            self._defaults = None
        for group_name in self._INPUT_GROUPS:
            group = getattr(self, group_name, None)
            if not isinstance(group, dict):
                continue
            for key, widget in group.items():
                self._refresh_widget_style(widget, key)

    def _refresh_widget_style(self, widget, key: str) -> None:
        """Совместить modified (цвет текста) и search (фон)."""
        parts: list[str] = []
        if self._defaults is not None:
            default = getattr(self._defaults, key, None)
            if default is not None:
                try:
                    if self._widget_differs(widget, default):
                        parts.append(self._MARK_STYLE)
                except Exception:
                    pass
        if self._search_text and self._is_search_match(widget, key):
            parts.append("background-color: #4a4a10;")
        widget.setStyleSheet(" ".join(parts))

    def _is_search_match(self, widget, key: str) -> bool:
        if not self._search_text:
            return False
        hay = (key + " " + (widget.toolTip() or "")).lower()
        return self._search_text in hay

    def _focus_search(self) -> None:
        self._search_line.setFocus()
        self._search_line.selectAll()

    def eventFilter(self, obj, event):
        """Esc в поле поиска: если текст есть — очистить, иначе blur."""
        from PySide6.QtCore import QEvent
        from PySide6.QtCore import Qt as _Qt
        if obj is getattr(self, "_search_line", None):
            if event.type() == QEvent.Type.KeyPress:
                if event.key() == _Qt.Key.Key_Escape:
                    if self._search_line.text():
                        self._search_line.clear()
                    else:
                        self._search_line.clearFocus()
                    return True
        return super().eventFilter(obj, event)

    def _apply_search(self, text: str) -> None:
        self._search_text = (text or "").strip().lower()
        self._check_modified()
        hint = getattr(self, "_search_hint", None)
        if not self._search_text:
            self._notify_status("")
            if hint is not None:
                hint.setText("")
            return
        count = sum(
            1
            for g in self._INPUT_GROUPS
            for k, w in getattr(self, g, {}).items()
            if self._is_search_match(w, k)
        )
        msg = f"Найдено полей: {count}"
        if hint is not None:
            hint.setText(msg)
        self._notify_status(msg)

    @staticmethod
    def _widget_differs(widget, default) -> bool:
        from PySide6.QtWidgets import (
            QCheckBox, QDoubleSpinBox, QLineEdit,
            QPlainTextEdit, QSpinBox,
        )
        if isinstance(widget, QSpinBox):
            return int(widget.value()) != int(default)
        if isinstance(widget, QDoubleSpinBox):
            return abs(float(widget.value()) - float(default)) > 1e-9
        if isinstance(widget, QCheckBox):
            return bool(widget.isChecked()) != bool(default)
        if isinstance(widget, QLineEdit):
            return widget.text().strip() != str(default)
        if isinstance(widget, EditableListWidget):
            current_list = widget.items()
            if isinstance(default, tuple):
                return tuple(current_list) != default
            if isinstance(default, frozenset):
                if default and isinstance(next(iter(default)), int):
                    try:
                        current_set = frozenset(int(x) for x in current_list)
                    except ValueError:
                        return True
                    return current_set != default
                return frozenset(current_list) != default
            return False
        if isinstance(widget, QPlainTextEdit):
            text = widget.toPlainText()
            if isinstance(default, tuple):
                current = tuple(
                    line.strip() for line in text.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
                return current != default
            if isinstance(default, frozenset):
                if default and isinstance(next(iter(default)), int):
                    current = _parse_ports(text)
                else:
                    current = _parse_lines(text)
                return current != default
        return False

    def goto(self, key: str) -> None:
        for i in range(self._sidebar.count()):
            item = self._sidebar.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == key:
                self._sidebar.setCurrentRow(i)
                return

    # =========================================================================
    # ОБЩИЕ ХЕЛПЕРЫ ПОСТРОЕНИЯ СЕКЦИЙ
    # =========================================================================

    def _make_scroll_form(self):
        """QScrollArea + QFormLayout внутри. Возвращает (scroll, form, host).

        Все секции однотипны: заголовок, подпись, прокручиваемая форма,
        кнопки снизу. Хелпер убирает дублирование.
        """
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        host = QWidget()
        form = QFormLayout(host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(14)
        # Label слева, верхнее выравнивание — чтобы название поля было
        # на одном уровне со спиннером, а описание уходило под ним.
        form.setLabelAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        form.setFormAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        # FieldsStayAtSizeHint — спиннеры фикс. ширины. Label-колонке
        # это не мешает растягиваться: у label-виджета Expanding, а
        # форма при нехватке места отдаёт свободное место ему.
        form.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint
        )
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.DontWrapRows)
        scroll.setWidget(host)
        return scroll, form

    def _make_header(self, title: str, subtitle: str) -> tuple[QLabel, QLabel]:
        t = QLabel(title)
        t.setObjectName("h1")
        s = QLabel(subtitle)
        s.setObjectName("muted")
        s.setWordWrap(True)
        section_key = SECTION_BY_TITLE.get(title)
        if section_key:
            help_text = get_section_help(section_key)
            if help_text:
                t.setToolTip(help_text)
                s.setToolTip(help_text)
        return t, s

    def _make_buttons(self, reset_slot, apply_slot) -> QHBoxLayout:
        h = QHBoxLayout()
        h.addStretch(1)
        rst = QPushButton("Сбросить к default")
        rst.clicked.connect(reset_slot)
        apt = QPushButton("Применить")
        apt.setObjectName("primary")
        apt.clicked.connect(apply_slot)
        h.addWidget(rst)
        h.addWidget(apt)
        return h

    # =========================================================================
    # ПРОФИЛИ
    # =========================================================================

    def _build_profile_row(self):
        from PySide6.QtWidgets import QComboBox, QLabel, QHBoxLayout, QPushButton

        row = QHBoxLayout()
        row.setSpacing(8)

        row.addWidget(QLabel("Профиль:"))
        self._profile_combo = QComboBox()
        self._profile_combo.setFixedWidth(240)
        for p in ALL_PROFILES:
            self._profile_combo.addItem(p.title, p.key)
        # Установить текущий
        idx = self._profile_combo.findData(self._active_profile_key)
        if idx >= 0:
            self._profile_combo.setCurrentIndex(idx)
        self._profile_combo.currentIndexChanged.connect(
            self._on_profile_combo_changed
        )
        row.addWidget(self._profile_combo)

        apply_btn = QPushButton("Применить профиль")
        apply_btn.clicked.connect(self._apply_active_profile)
        row.addWidget(apply_btn)

        row.addStretch(1)

        self._profile_hint = QLabel("")
        self._profile_hint.setObjectName("muted")
        self._profile_hint.setWordWrap(True)
        row.addWidget(self._profile_hint, stretch=2)

        self._update_profile_hint()
        return row

    def _on_profile_combo_changed(self, index: int) -> None:
        key = self._profile_combo.itemData(index) or DEFAULT_PROFILE_KEY
        self._active_profile_key = key
        self._update_profile_hint()

    def _update_profile_hint(self) -> None:
        p = get_profile(self._active_profile_key)
        if p is None:
            self._profile_hint.setText("")
            return
        n_ov = len(p.overrides)
        n_dd = len(p.disabled_detectors)
        n_dc = len(p.disabled_contradictions)
        parts = [p.description]
        if n_ov or n_dd or n_dc:
            parts.append(
                f"(параметров: {n_ov}, "
                f"отключённых детекторов: {n_dd}, "
                f"правил: {n_dc})"
            )
        self._profile_hint.setText(" ".join(parts))

    def _apply_active_profile(self) -> None:
        """Применить выбранный профиль: заполнить виджеты и эмитить сигналы."""
        p = get_profile(self._active_profile_key)
        if p is None:
            return

        # 1) Заполнить виджеты Порогов значениями из профиля,
        #    остальные — дефолтами из Config.
        try:
            from pcap_triage.config import Config
            cfg = Config()
        except ImportError:
            cfg = None

        for key, widget in self._threshold_inputs.items():
            if key in p.overrides:
                value = p.overrides[key]
            elif cfg is not None:
                value = getattr(cfg, key, None)
            else:
                continue
            self._set_widget_value(widget, value, key)

        # 2) Обновить чекбоксы детекторов и противоречий.
        for name, cb in self._detector_boxes.items():
            cb.setChecked(name not in p.disabled_detectors)
        for name, cb in self._contradiction_boxes.items():
            cb.setChecked(name not in p.disabled_contradictions)

        # 3) Сохранить активный профиль и эмитить сигналы.
        self._save_active_profile(p.key)

        thresholds_values = {}
        for key, widget in self._threshold_inputs.items():
            if hasattr(widget, "value"):
                thresholds_values[key] = widget.value()
        if thresholds_values:
            self.thresholds_applied.emit(thresholds_values)

        self.detectors_applied.emit(set(p.disabled_detectors))
        self.contradictions_applied.emit(set(p.disabled_contradictions))

    def _read_active_profile(self) -> str:
        if self._store is None:
            return DEFAULT_PROFILE_KEY
        data = self._store.load()
        key = data.get("active_profile", DEFAULT_PROFILE_KEY)
        return key if get_profile(key) is not None else DEFAULT_PROFILE_KEY

    def _save_active_profile(self, key: str) -> None:
        if self._store is None:
            return
        current = self._store.load()
        current["active_profile"] = key
        self._store.save(current)

    # =========================================================================
    # СЕКЦИЯ: Пороги
    # =========================================================================

    def _build_general_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Общие настройки",
            "Базовые параметры интерфейса.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        form = QFormLayout()
        form.setSpacing(14)

        self._lang_combo = QComboBox()
        self._lang_combo.addItem("Русский", "ru")
        self._lang_combo.addItem("English", "en")

        # Загружаем текущий язык
        if self._store:
            current_lang = self._store.load().get("language", "ru")
            idx = self._lang_combo.findData(current_lang)
            if idx >= 0:
                self._lang_combo.setCurrentIndex(idx)

        self._lang_combo.currentIndexChanged.connect(self._on_lang_changed)
        form.addRow("Язык интерфейса:", self._lang_combo)
        outer.addLayout(form)
        outer.addStretch(1)
        return w

    def _on_lang_changed(self, index: int) -> None:
        lang = self._lang_combo.itemData(index)
        if self._store and lang:
            self._store.save_partial(language=lang)
            QMessageBox.information(
                self, "Язык",
                "Язык изменён. Для полного применения перезапустите программу.",
            )

    def _build_thresholds_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Пороги",
            "Пороги детекторов из Config ядра. Изменения применяются "
            "к следующему прогону. Профиль — готовый набор значений.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        outer.addLayout(self._build_profile_row())

        scroll, form = self._make_scroll_form()
        self._threshold_inputs: dict[str, object] = {}

        self._add_int_row(form, "dga_min_label_length", "DGA: минимальная длина label")
        self._add_float_row(form, "dga_entropy_threshold", "DGA: порог энтропии", step=0.1)
        self._add_int_row(form, "nxdomain_burst_threshold", "NXDOMAIN burst: порог")
        self._add_int_row(form, "nxdomain_burst_window_sec",
                          "NXDOMAIN burst: окно (сек)", lo=1, hi=86400)
        self._add_float_row(form, "nxdomain_burst_min_ratio",
                            "NXDOMAIN burst: мин. доля NXDOMAIN",
                            step=0.05, lo=0.0, hi=1.0)
        self._add_int_row(form, "dns_tunneling_min_qname_length", "DNS tunneling: мин. длина qname")
        self._add_int_row(form, "dns_tunneling_min_queries", "DNS tunneling: мин. запросов")
        self._add_int_row(form, "brute_force_min_flows", "Brute force: мин. flows")
        self._add_int_row(form, "brute_force_max_avg_packets", "Brute force: макс. avg packets")
        self._add_int_row(form, "ftp_brute_force_min_flows", "FTP brute force: мин. flows")
        self._add_int_row(form, "beaconing_min_connections", "Beaconing: мин. соединений")
        self._add_int_row(form, "beaconing_min_duration_sec", "Beaconing: мин. длительность (сек)")
        self._add_float_row(form, "beaconing_max_jitter_ratio", "Beaconing: макс. jitter", step=0.01)
        self._add_int_row(form, "large_transfer_min_bytes", "Large transfer: мин. байт")
        self._add_int_row(form, "port_scan_min_distinct_dsts", "Port scan: мин. dsts")
        self._add_int_row(form, "port_scan_max_flows_per_dst", "Port scan: макс. flows/dst")
        self._add_float_row(form, "reverse_asymmetry_min_ratio", "Reverse asymmetry: мин. ratio", step=0.5)
        self._add_int_row(form, "reverse_asymmetry_min_total_bytes", "Reverse asymmetry: мин. байт")

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_thresholds, self._apply_thresholds))

        self._load_thresholds()
        return w

    def _label_with_hint(self, label_text: str, key: str):
        """QWidget: [label сверху] [hint под ним серым].

        Хост растягивается по горизонтали (Expanding), чтобы QFormLayout
        отдал описанию всю доступную ширину. Спиннер справа остаётся
        фиксированной ширины (160px) — он не участвует в stretch.
        """
        from PySide6.QtWidgets import QSizePolicy
        from pcap_triage_gui.field_help import get_field_help

        host = QWidget()
        host.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred,
        )
        # QFormLayout при FieldsStayAtSizeHint отдаёт label-колонке
        # ровно sizeHint. Без явного минимума Expanding игнорируется.
        host.setMinimumWidth(620)
        v = QVBoxLayout(host)
        v.setContentsMargins(0, 0, 12, 6)
        v.setSpacing(2)

        lbl = QLabel(label_text)
        v.addWidget(lbl)

        text = get_field_help(key)
        hint = QLabel(text)
        hint.setWordWrap(True)
        hint.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred,
        )
        hint.setStyleSheet("color: #8a8a9a; font-size: 11px;")
        hint.setToolTip(text)
        v.addWidget(hint)

        if not hasattr(self, "_field_hints"):
            self._field_hints: dict[str, QLabel] = {}
        self._field_hints[key] = hint
        return host



    def _add_int_row(self, form, key: str, label: str,
                     lo: int = 0, hi: int = 1_000_000_000) -> None:
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._threshold_inputs[key] = sp

    def _add_float_row(self, form, key: str, label: str,
                       step: float = 0.1, lo: float = 0.0,
                       hi: float = 1000.0) -> None:
        sp = QDoubleSpinBox()
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setDecimals(3)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._threshold_inputs[key] = sp

    def _load_thresholds(self) -> None:
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._threshold_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(widget, QSpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, QDoubleSpinBox):
                widget.setValue(float(value))

    def _reset_thresholds(self) -> None:
        self._load_thresholds()

    def _apply_thresholds(self) -> None:
        values = {}
        for key, widget in self._threshold_inputs.items():
            if isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QDoubleSpinBox):
                values[key] = widget.value()
        self.thresholds_applied.emit(values)

    # =========================================================================
    # СЕКЦИЯ: Brute force
    # =========================================================================

    def _build_brute_force_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Brute force",
            "Как детектор отличает подбор пароля от обычного трафика. "
            "Пороги «сколько flows» — в разделе Пороги.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._brute_inputs: dict[str, object] = {}

        self._add_int_row_bf(form, "brute_force_min_unique_src_ports",
                             "HTTP: мин. уникальных src-портов", lo=1, hi=10000)
        self._add_float_row_bf(form, "brute_force_uri_ratio_threshold",
                               "HTTP: доля запросов к login-endpoint",
                               lo=0.01, hi=1.0, step=0.05, decimals=2)
        self._add_float_row_bf(form, "brute_force_min_rate_flows_per_sec",
                               "HTTP: мин. скорость (flows/сек)",
                               lo=0.001, hi=1000.0, step=0.01, decimals=3)
        self._add_int_row_bf(form, "ftp_brute_force_min_unique_src_ports",
                             "FTP: мин. уникальных src-портов", lo=1, hi=10000)

        self._bf_skip_tls = EditableListWidget(port_mode=True)
        form.addRow("HTTP: порты, где brute force не ищем (TLS)", self._bf_skip_tls)
        self._brute_inputs["brute_force_skip_tls_ports"] = self._bf_skip_tls

        self._bf_login_hints = EditableListWidget(port_mode=False)
        form.addRow("HTTP: подсказки login-endpoint", self._bf_login_hints)
        self._brute_inputs["login_endpoint_hints"] = self._bf_login_hints

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_brute_force, self._apply_brute_force))

        self._load_brute_force()
        return w

    def _add_int_row_bf(self, form, key, label, lo, hi):
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._brute_inputs[key] = sp

    def _add_float_row_bf(self, form, key, label, lo, hi, step, decimals):
        sp = QDoubleSpinBox()
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setDecimals(decimals)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._brute_inputs[key] = sp

    def _load_brute_force(self) -> None:
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._brute_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(widget, QSpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, QDoubleSpinBox):
                widget.setValue(float(value))
            elif isinstance(widget, (QPlainTextEdit, EditableListWidget)):
                if isinstance(value, frozenset):
                    if value and isinstance(next(iter(value)), int):
                        widget.setPlainText(_format_ports(value))
                    else:
                        widget.setPlainText(_format_lines(value))

    def _apply_brute_force(self) -> None:
        values: dict = {}
        skipped_total = 0
        previews: list[str] = []
        for key, widget in self._brute_inputs.items():
            if isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QDoubleSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QPlainTextEdit):
                text = widget.toPlainText()
                if "ports" in key or "skip_tls" in key:
                    parsed, skipped = _parse_ports_with_report(text)
                    values[key] = parsed
                    skipped_total += len(skipped)
                    if skipped:
                        previews.append(f"{key}: {', '.join(skipped[:3])}")
                else:
                    values[key] = _parse_lines(text)
        if skipped_total:
            self._notify_status(
                f"Пропущено невалидных токенов: {skipped_total} "
                f"({'; '.join(previews[:2])})",
                level="warn",
            )
        self.config_applied.emit(values)

    # =========================================================================
    # СЕКЦИЯ: Сеть
    # =========================================================================

    def _build_network_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Сеть",
            "Списки портов и префиксов. Вводите через запятую или с новой строки. "
            "Невалидные значения подсвечиваются и не сохраняются.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._network_inputs: dict[str, object] = {}
        self._network_status: dict[str, QLabel] = {}

        self._add_smart_net_row(form, "suspicious_ports", "Подозрительные порты", is_net=False)
        self._add_smart_net_row(form, "port_scan_excluded_ports", "Исключения port scan", is_net=False)
        self._add_smart_net_row(form, "dc_service_ports", "Порты domain controller", is_net=False)
        self._add_smart_net_row(form, "lateral_movement_ports", "Порты lateral movement", is_net=False)
        self._add_smart_net_row(form, "beaconing_mail_polling_ports", "Порты mail-polling (POP3/IMAP)", is_net=False)
        self._add_smart_net_row(form, "private_networks", "Префиксы приватных сетей", is_net=True)

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_network, self._apply_network))

        self._load_network()
        return w

    def _add_smart_net_row(self, form, key, label, is_net=False):
        container = QWidget()
        vbox = QVBoxLayout(container)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(4)

        te = QPlainTextEdit()
        te.setFixedHeight(60)
        te.setPlaceholderText("Например: 10.0.0.0/8" if is_net else "Например: 80, 443, 8080")

        status_lbl = QLabel("")
        status_lbl.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        status_lbl.setWordWrap(True)

        vbox.addWidget(te)
        vbox.addWidget(status_lbl)
        form.addRow(label, container)

        self._network_inputs[key] = te
        self._network_status[key] = status_lbl

        te.setProperty("is_net", is_net)
        te.textChanged.connect(lambda w=te, k=key: self._validate_and_preview_net(w, k))

    def _validate_and_preview_net(self, widget: QPlainTextEdit, key: str) -> None:
        text = widget.toPlainText().strip()
        is_net = widget.property("is_net")
        status_lbl = self._network_status[key]

        if not text:
            widget.setStyleSheet("")
            status_lbl.setText("")
            return

        tokens = [t for t in re.split(r'[\s,]+', text) if t]

        if is_net:
            valid, invalid = [], []
            for t in tokens:
                if re.match(r'^[0-9\./]+$', t):
                    valid.append(t)
                else:
                    invalid.append(t)

            if invalid:
                widget.setStyleSheet("border: 1px solid #ff5555;")
                status_lbl.setText(f"<span style='color:#ff5555;'>Ошибка в: {', '.join(set(invalid))}</span>")
            else:
                widget.setStyleSheet("")
                status_lbl.setText(f"Будет сохранено: {', '.join(valid)}")
        else:
            valid, invalid = [], []
            for t in tokens:
                if t.isdigit() and 1 <= int(t) <= 65535:
                    valid.append(str(int(t)))
                else:
                    invalid.append(t)

            if invalid:
                widget.setStyleSheet("border: 1px solid #ff5555;")
                status_lbl.setText(f"<span style='color:#ff5555;'>Невалидные порты: {', '.join(set(invalid))}</span>")
            else:
                sorted_valid = sorted(list(set(int(p) for p in valid)))
                widget.setStyleSheet("")
                status_lbl.setText(f"Будет сохранено ({len(sorted_valid)}): {', '.join(map(str, sorted_valid))}")

    def _load_network(self) -> None:
        try:
            from pcap_triage.config import Config
            cfg = Config()
        except ImportError:
            return
        for key, widget in self._network_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(value, frozenset):
                if value and isinstance(next(iter(value)), int):
                    widget.setPlainText(_format_ports(value))
                else:
                    widget.setPlainText(_format_lines(value))
            elif isinstance(value, tuple):
                widget.setPlainText("\n".join(value))

    def _apply_network(self) -> None:
        values: dict = {}
        for key, widget in self._network_inputs.items():
            text = widget.toPlainText().strip()
            is_net = widget.property("is_net")
            tokens = [t for t in re.split(r'[\s,]+', text) if t]

            if is_net:
                valid = tuple(t for t in tokens if re.match(r'^[0-9\./]+$', t))
                values[key] = valid
            else:
                valid_ports = set()
                for t in tokens:
                    if t.isdigit() and 1 <= int(t) <= 65535:
                        valid_ports.add(int(t))
                values[key] = frozenset(valid_ports)

        self.config_applied.emit(values)



    # =========================================================================
    # СЕКЦИЯ: Производительность
    # =========================================================================

    def _build_performance_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Производительность",
            "Компромисс между глубиной анализа и скоростью. "
            "Технические лимиты (память, размеры) скрыты и работают "
            "по умолчанию.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        host = QWidget()
        form = QFormLayout(host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(16)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        scroll.setWidget(host)

        self._perf_inputs: dict[str, object] = {}

        # --- TCP Reassembly ---
        cb_reassembly = QCheckBox("Склеивать TCP-сегменты (TCP Reassembly)")
        lbl_reassembly = QLabel(
            "<span style='color:#a0a0b0; font-size:11px;'>"
            "Собирает полные HTTP-запросы и TLS-хендшейки. "
            "Выключите для максимальной скорости."
            "</span>"
        )
        lbl_reassembly.setTextFormat(Qt.TextFormat.RichText)
        form.addRow(cb_reassembly, lbl_reassembly)
        self._perf_inputs["tcp_reassembly_enabled"] = cb_reassembly
        if not hasattr(self, "_field_hints"): self._field_hints = {}
        self._field_hints["tcp_reassembly_enabled"] = lbl_reassembly

        # --- File Carve ---
        cb_carve = QCheckBox("Извлекать метаданные файлов (File Carve)")
        lbl_carve = QLabel(
            "<span style='color:#a0a0b0; font-size:11px;'>"
            "Находит скачанные скрипты и бинарники (SHA256, MIME). "
            "Тело файла на диск не пишется."
            "</span>"
        )
        lbl_carve.setTextFormat(Qt.TextFormat.RichText)
        form.addRow(cb_carve, lbl_carve)
        self._perf_inputs["file_carve_enabled"] = cb_carve
        if not hasattr(self, "_field_hints"): self._field_hints = {}
        self._field_hints["file_carve_enabled"] = lbl_carve

        cb_write = QCheckBox("Сохранять тела файлов на диск (ОПАСНО)")
        lbl_write = QLabel(
            "<span style='color:#ff5555; font-size:11px;'>"
            "Создает файлы в reports/carved/. Включайте только "
            "если уверены в безопасности."
            "</span>"
        )
        lbl_write.setTextFormat(Qt.TextFormat.RichText)
        form.addRow(cb_write, lbl_write)
        self._perf_inputs["file_carve_write_body"] = cb_write
        if not hasattr(self, "_field_hints"): self._field_hints = {}
        self._field_hints["file_carve_write_body"] = lbl_write

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_performance, self._apply_performance))

        self._load_performance()
        return w

    def _load_performance(self) -> None:
        try:
            from pcap_triage.config import Config
            cfg = Config()
            for key, widget in self._perf_inputs.items():
                val = getattr(cfg, key, None)
                if val is not None and isinstance(widget, QCheckBox):
                    widget.setChecked(bool(val))
        except ImportError:
            pass

    def _apply_performance(self) -> None:
        values = {}
        for key, widget in self._perf_inputs.items():
            if isinstance(widget, QCheckBox):
                values[key] = widget.isChecked()
        self.config_applied.emit(values)


    def _add_bool_row(self, form, key, label):
        cb = QCheckBox()
        form.addRow(self._label_with_hint(label, key), cb)
        self._perf_inputs[key] = cb

    def _add_int_row_pf(self, form, key, label, lo, hi):
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setFixedWidth(180)
        form.addRow(self._label_with_hint(label, key), sp)
        self._perf_inputs[key] = sp

    def _load_performance(self) -> None:
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._perf_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(widget, QCheckBox):
                widget.setChecked(bool(value))
            elif isinstance(widget, QSpinBox):
                widget.setValue(int(value))

    def _apply_performance(self) -> None:
        values: dict = {}
        for key, widget in self._perf_inputs.items():
            if isinstance(widget, QCheckBox):
                values[key] = widget.isChecked()
            elif isinstance(widget, QSpinBox):
                values[key] = widget.value()
        self.config_applied.emit(values)

    # =========================================================================
    # СЕКЦИЯ: Allowlist
    # =========================================================================

    def _build_allowlist_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Allowlist",
            "Белые списки. Совпадение с элементом убирает кандидата из "
            "findings. Один элемент на строку, # — комментарий.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._allowlist_inputs: dict[str, object] = {}

        self._add_list_row_al(form, "beaconing_allowlist_suffixes",
                              "Beaconing: суффиксы SNI/Host (analytics, CDN)",
                              height=200)
        self._add_list_row_al(form, "beaconing_allowlist_ips",
                              "Beaconing: точные IP (без SNI)",
                              height=80)
        self._add_list_row_al(form, "dns_tunneling_allowlist",
                              "DNS tunneling: DoH-домены, не считать туннелем",
                              height=80)
        self._add_list_row_al(form, "sni_mismatch_allowlist",
                              "SNI mismatch: известные проверочные домены",
                              height=140)
        self._add_list_row_al(form, "large_transfer_excluded_hosts",
                              "Large transfer: хосты, для которых это норма",
                              height=120)
        self._add_list_row_al(form, "large_transfer_excluded_user_agents",
                              "Large transfer: UA, для которых это норма",
                              height=80)

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_allowlist, self._apply_allowlist))

        self._load_allowlist()
        return w

    def _add_list_row_al(self, form, key, label, height=90):
        from pcap_triage_gui.field_help import get_field_help
        w = EditableListWidget(
            port_mode=(key in PORT_FIELDS),
            help_text=get_field_help(key),
        )
        form.addRow(label, w)
        self._allowlist_inputs[key] = w

    def _load_allowlist(self) -> None:
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._allowlist_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(value, (frozenset, tuple, set, list)):
                widget.setPlainText(_format_lines(value))

    def _apply_allowlist(self) -> None:
        values: dict = {}
        for key, widget in self._allowlist_inputs.items():
            values[key] = _parse_lines(widget.toPlainText())
        self.config_applied.emit(values)

    # =========================================================================
    # СЕКЦИЯ: DGA
    # =========================================================================

    def _build_dga_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "DGA",
            "Итоговый allowlist детектора DGA. Сюда сливаются домены "
            "cloud tunnel и IP-check сервисов из Config. Удаление "
            "элемента означает, что DGA начнёт ругаться на него.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._dga_inputs: dict[str, object] = {}

        self._dga_allowlist = EditableListWidget(port_mode=False)
        form.addRow("DGA allowlist (домены)", self._dga_allowlist)
        self._dga_inputs["dga_allowlist"] = self._dga_allowlist

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_dga, self._apply_dga))

        self._load_dga()
        return w

    def _load_dga(self) -> None:
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
        value = getattr(cfg, "dga_allowlist", None)
        if value:
            self._dga_allowlist.setPlainText(_format_lines(value))

    def _apply_dga(self) -> None:
        values = {
            "dga_allowlist": _parse_lines(self._dga_allowlist.toPlainText()),
        }
        self.config_applied.emit(values)

    # =========================================================================
    # СЕКЦИЯ: YARA
    # =========================================================================




    def _validate_yara_rules(self) -> None:
        try:
            import yara
        except ImportError:
            QMessageBox.warning(self, "YARA", "Модуль yara-python не установлен.\nЗапустите: pip install yara-python")
            return

        path = self._yara_path.text().strip()
        if not path:
            QMessageBox.warning(self, "YARA", "Укажите путь к файлу правил (.yar)")
            return

        try:
            rules = yara.compile(filepath=path)
            QMessageBox.information(self, "YARA", f"Успешно! Загружено правил: {sum(1 for _ in rules)}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка в правилах", f"{type(e).__name__}:\n{e}")



    # =========================================================================
    # СЕКЦИЯ: Отчёты
    # =========================================================================

    def _build_reports_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Отчёты",
            "Куда ядро складывает артефакты (кэш обогащения, carved files "
            "при включённой записи). Путь создаётся при применении.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._reports_inputs: dict[str, object] = {}

        self._output_dir = QLineEdit()
        self._output_dir.setPlaceholderText("reports")
        self._output_dir.setFixedWidth(420)
        form.addRow("Каталог отчётов (output_dir)", self._output_dir)
        self._reports_inputs["output_dir"] = self._output_dir

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_reports, self._apply_reports))

        self._load_reports()
        return w

    def _load_reports(self) -> None:
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
        value = getattr(cfg, "output_dir", None)
        if value is not None:
            self._output_dir.setText(str(value))

    def _apply_reports(self) -> None:
        text = self._output_dir.text().strip() or "reports"
        path = Path(text)
        # Создаём сразу: Config.__post_init__ делает mkdir только для
        # дефолтного пути. При override через object.__setattr__ пост-
        # инициализация не запускается, поэтому папка останется не
        # созданной, и ядро упадёт при попытке писать.
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Не критично: если путь невалидный, ядро само отвалится
            # позже с понятной ошибкой. Молча пропускаем.
            pass
        self.config_applied.emit({"output_dir": path})

    # =========================================================================
    # СЕКЦИЯ: Threat Intel
    # =========================================================================

    # =========================================================================
    # СЕКЦИЯ: YARA
    # =========================================================================





    # =========================================================================
    # СЕКЦИЯ: Threat Intel
    # =========================================================================

    # =========================================================================
    # СЕКЦИЯ: YARA
    # =========================================================================

    def _build_yara_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "YARA",
            "Пользовательские YARA-правила для поиска сигнатур в payload. "
            "Если файл не выбран, используются стандартные правила из ядра.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._yara_inputs = {}

        self._yara_path = QLineEdit()
        self._yara_path.setPlaceholderText("По умолчанию (rules/default.yar)")
        self._yara_path.setFixedWidth(420)

        btn_browse = QPushButton("Обзор…")
        btn_browse.clicked.connect(self._browse_yara_file)

        btn_validate = QPushButton("Проверить правила")
        btn_validate.clicked.connect(self._validate_yara_rules)

        row = QHBoxLayout()
        row.addWidget(self._yara_path)
        row.addWidget(btn_browse)
        row.addWidget(btn_validate)
        row.addStretch(1)

        form.addRow("Путь к файлу правил (.yar):", row)
        self._yara_inputs["yara_rules_path"] = self._yara_path

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_yara, self._apply_yara))

        self._load_yara()
        return w

    def _browse_yara_file(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать YARA-файл", "",
            "YARA Rules (*.yar *.yara);;Все файлы (*)"
        )
        if path:
            self._yara_path.setText(path)

    def _load_yara(self) -> None:
        try:
            from pcap_triage.config import Config
            cfg = Config()
            val = getattr(cfg, "yara_rules_path", None)
            if val:
                self._yara_path.setText(str(val))
            else:
                self._yara_path.clear()
        except ImportError:
            pass

    def _apply_yara(self) -> None:
        text = self._yara_path.text().strip()
        values = {"yara_rules_path": text if text else None}
        self.config_applied.emit(values)

    def _build_threatintel_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Threat Intel",
            "Обогащение IOC из findings. Запускается отдельно (флаг "
            "--enrich). API-ключи живут до перезапуска GUI — ядро читает "
            "их из переменных окружения в момент запроса.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        host = QWidget()
        host.setMaximumWidth(760)
        form = QFormLayout(host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        scroll.setWidget(host)

        self._ti_inputs: dict[str, object] = {}

        # --- Провайдеры ---
        te_prov = QPlainTextEdit()
        te_prov.setFixedHeight(80)
        te_prov.setMaximumWidth(500)
        form.addRow("Активные провайдеры", te_prov)
        self._ti_inputs["enrichment_enabled_providers"] = te_prov

        # --- API-ключи ---
        self._ti_abuse_key = QLineEdit()
        self._ti_abuse_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_abuse_key.setPlaceholderText("ABUSEIPDB_API_KEY")
        self._ti_abuse_key.setMaximumWidth(420)
        form.addRow("AbuseIPDB API key", self._ti_abuse_key)

        self._ti_vt_key = QLineEdit()
        self._ti_vt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_vt_key.setPlaceholderText("VIRUSTOTAL_API_KEY")
        self._ti_vt_key.setMaximumWidth(420)
        form.addRow("VirusTotal API key", self._ti_vt_key)

        self._ti_abusech_key = QLineEdit()
        self._ti_abusech_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_abusech_key.setPlaceholderText("ABUSECH_AUTH_KEY (MalwareBazaar, ThreatFox, URLhaus)")
        self._ti_abusech_key.setMaximumWidth(420)
        form.addRow("abuse.ch Auth-Key", self._ti_abusech_key)

        self._ti_otx_key = QLineEdit()
        self._ti_otx_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_otx_key.setPlaceholderText("OTX_API_KEY")
        self._ti_otx_key.setMaximumWidth(420)
        form.addRow("AlienVault OTX API key", self._ti_otx_key)

        self._ti_greynoise_key = QLineEdit()
        self._ti_greynoise_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_greynoise_key.setPlaceholderText("GREYNOISE_API_KEY")
        self._ti_greynoise_key.setMaximumWidth(420)
        form.addRow("GreyNoise API key", self._ti_greynoise_key)

        self._ti_urlscan_key = QLineEdit()
        self._ti_urlscan_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_urlscan_key.setPlaceholderText("URLSCAN_API_KEY")
        self._ti_urlscan_key.setMaximumWidth(420)
        form.addRow("URLScan API key", self._ti_urlscan_key)

        show_cb = QCheckBox("Показать ключи")
        show_cb.toggled.connect(self._toggle_api_keys_visibility)
        form.addRow("", show_cb)

        shodan_note = QLabel(
            "<span style='color:#a0a0b0; font-size:11px;'>"
            "Shodan InternetDB не требует ключа — работает из коробки."
            "</span>"
        )
        shodan_note.setTextFormat(Qt.TextFormat.RichText)
        form.addRow("", shodan_note)

        # --- Кэш ---
        sp_ttl = QSpinBox()
        sp_ttl.setRange(1, 365)
        sp_ttl.setFixedWidth(120)
        form.addRow("Кэш: TTL (дней)", sp_ttl)
        self._ti_inputs["enrichment_cache_ttl_days"] = sp_ttl

        le_cache = QLineEdit()
        le_cache.setMaximumWidth(420)
        form.addRow("Кэш: путь к SQLite-файлу", le_cache)
        self._ti_inputs["enrichment_cache_path"] = le_cache

        # --- Лимит IOC ---
        sp_max = QSpinBox()
        sp_max.setRange(1, 10000)
        sp_max.setFixedWidth(120)
        form.addRow("Максимум IOC за прогон", sp_max)
        self._ti_inputs["enrichment_max_iocs"] = sp_max

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(
            self._load_threatintel, self._apply_threatintel,
        ))

        self._load_threatintel()
        return w





    def _toggle_api_keys_visibility(self, visible: bool) -> None:
        """Показать/скрыть ключи в обоих полях. Полезно, когда копируешь
        длинный ключ и хочешь убедиться, что вставилось без обрезки.
        """
        mode = (
            QLineEdit.EchoMode.Normal if visible
            else QLineEdit.EchoMode.Password
        )
        self._ti_abuse_key.setEchoMode(mode)
        self._ti_vt_key.setEchoMode(mode)
        for _w in (
            getattr(self, "_ti_abusech_key", None),
            getattr(self, "_ti_otx_key", None),
            getattr(self, "_ti_greynoise_key", None),
            getattr(self, "_ti_urlscan_key", None),
        ):
            if _w is not None:
                _w.setEchoMode(mode)

    def _load_threatintel(self) -> None:
        """Заполнить поля из Config и SecretsStore (keyring/env)."""
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._ti_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(widget, QSpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, QLineEdit):
                widget.setText(str(value))
            elif isinstance(widget, (QPlainTextEdit, EditableListWidget)):
                if isinstance(value, (frozenset, tuple, set, list)):
                    widget.setPlainText(_format_lines(value))
        # Все ключи — через SecretsStore: keyring -> session -> env.
        self._ti_abuse_key.setText(self._secrets.get("abuseipdb_api_key"))
        self._ti_vt_key.setText(self._secrets.get("virustotal_api_key"))
        self._ti_abusech_key.setText(self._secrets.get("abusech_auth_key"))
        self._ti_otx_key.setText(self._secrets.get("otx_api_key"))
        self._ti_greynoise_key.setText(self._secrets.get("greynoise_api_key"))
        self._ti_urlscan_key.setText(self._secrets.get("urlscan_api_key"))
    def _apply_threatintel(self) -> None:
        """Сохранить ключи в keyring+env, поля Config — в config_applied."""
        key_widgets = {
            "abuseipdb_api_key": self._ti_abuse_key,
            "virustotal_api_key": self._ti_vt_key,
            "abusech_auth_key": self._ti_abusech_key,
            "otx_api_key": self._ti_otx_key,
            "greynoise_api_key": self._ti_greynoise_key,
            "urlscan_api_key": self._ti_urlscan_key,
        }
        for name, widget in key_widgets.items():
            # SecretsStore.set обновляет и keyring, и os.environ.
            self._secrets.set(name, widget.text())

        values: dict = {}
        for key, widget in self._ti_inputs.items():
            if isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QLineEdit):
                if key == "enrichment_cache_path":
                    text = widget.text().strip()
                    if text:
                        try:
                            Path(text).parent.mkdir(
                                parents=True, exist_ok=True,
                            )
                        except OSError:
                            pass
                        values[key] = Path(text)
            elif isinstance(widget, QPlainTextEdit):
                values[key] = _parse_lines(widget.toPlainText())
        self.config_applied.emit(values)

    # =========================================================================
    # СЕКЦИЯ: Детекторы
    # =========================================================================

    # =========================================================================
    # СЕКЦИЯ: Детекторы
    # =========================================================================

    def _build_detectors_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Детекторы",
            "Снятая галочка отключает детектор в следующем прогоне. "
            "Порядок совпадает с ядром.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        box_host = QWidget()
        box_layout = QVBoxLayout(box_host)
        box_layout.setContentsMargins(0, 8, 0, 8)
        box_layout.setSpacing(4)

        self._detector_boxes: dict[str, object] = {}
        for name, label in _DETECTORS:
            box_layout.addWidget(self._make_detector_row(name, label))
        box_layout.addStretch(1)

        scroll.setWidget(box_host)
        outer.addWidget(scroll, stretch=1)

        buttons = QHBoxLayout()
        all_btn = QPushButton("Включить все")
        all_btn.clicked.connect(lambda: self._set_all_detectors(True))
        none_btn = QPushButton("Отключить все")
        none_btn.clicked.connect(lambda: self._set_all_detectors(False))
        buttons.addWidget(all_btn)
        buttons.addWidget(none_btn)
        buttons.addStretch(1)
        apply_btn = QPushButton("Применить")
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_detectors)
        buttons.addWidget(apply_btn)
        outer.addLayout(buttons)

        return w

    def _make_detector_row(self, name: str, label: str) -> QWidget:
        """Строка детектора: [чекбокс с названием] [описание справа]."""
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 2, 0, 2)
        h.setSpacing(12)

        cb = QCheckBox(label)
        cb.setChecked(True)
        cb.setMinimumWidth(220)
        h.addWidget(cb)

        help_text = get_detector_help(name)
        hint = QLabel(help_text)
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8a8a9a; font-size: 11px;")
        hint.setToolTip(help_text)
        h.addWidget(hint, stretch=1)

        self._detector_boxes[name] = cb
        return row

    def _set_all_detectors(self, checked: bool) -> None:
        for cb in self._detector_boxes.values():
            cb.setChecked(checked)

    def _apply_detectors(self) -> None:
        disabled = {
            name for name, cb in self._detector_boxes.items()
            if not cb.isChecked()
        }
        self.detectors_applied.emit(disabled)

    # =========================================================================
    # СЕКЦИЯ: Противоречия
    # =========================================================================

    def _build_contradictions_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "ContradictionDetector",
            "Правила проверяют согласованность между слоями данных. "
            "Отключение правила убирает его из следующего прогона.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        box_host = QWidget()
        box_layout = QVBoxLayout(box_host)
        box_layout.setContentsMargins(0, 8, 0, 8)
        box_layout.setSpacing(4)

        self._contradiction_boxes: dict[str, object] = {}
        for name, label in _CONTRADICTIONS:
            box_layout.addWidget(self._make_contradiction_row(name, label))
        box_layout.addStretch(1)

        scroll.setWidget(box_host)
        outer.addWidget(scroll, stretch=1)

        buttons = QHBoxLayout()
        all_btn = QPushButton("Включить все")
        all_btn.clicked.connect(lambda: self._set_all_contradictions(True))
        none_btn = QPushButton("Отключить все")
        none_btn.clicked.connect(lambda: self._set_all_contradictions(False))
        buttons.addWidget(all_btn)
        buttons.addWidget(none_btn)
        buttons.addStretch(1)
        apply_btn = QPushButton("Применить")
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_contradictions)
        buttons.addWidget(apply_btn)
        outer.addLayout(buttons)

        return w

    def _make_contradiction_row(self, name: str, label: str) -> QWidget:
        """Строка правила: [чекбокс] [описание справа]."""
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 2, 0, 2)
        h.setSpacing(12)

        cb = QCheckBox(label)
        cb.setChecked(True)
        cb.setMinimumWidth(320)
        h.addWidget(cb)

        help_text = get_contradiction_help(name)
        hint = QLabel(help_text)
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8a8a9a; font-size: 11px;")
        hint.setToolTip(help_text)
        h.addWidget(hint, stretch=1)

        self._contradiction_boxes[name] = cb
        return row

    def _set_all_contradictions(self, checked: bool) -> None:
        for cb in self._contradiction_boxes.values():
            cb.setChecked(checked)

    def _apply_contradictions(self) -> None:
        disabled = {
            name for name, cb in self._contradiction_boxes.items()
            if not cb.isChecked()
        }
        self.contradictions_applied.emit(disabled)

    # =========================================================================
    # PERSISTENCE (settings_store)
    # =========================================================================

    def load_from_store(self) -> None:
        """Накатить сохранённые настройки поверх дефолтов при старте."""
        if self._store is None:
            return
        data = self._store.load()
        overrides = data.get("overrides", {})
        if not isinstance(overrides, dict):
            overrides = {}

        try:
            from pcap_triage.config import Config
            defaults = Config()
        except ImportError:
            defaults = None

        for group in (
            self._threshold_inputs,
            self._brute_inputs,
            self._network_inputs,
            self._perf_inputs,
            self._allowlist_inputs,
            self._dga_inputs,
            self._reports_inputs,
            self._ti_inputs,
        ):
            for key, widget in group.items():
                if key not in overrides:
                    continue
                if defaults is not None:
                    default = getattr(defaults, key, None)
                    value = rehydrate(default, overrides[key]) if default is not None else overrides[key]
                else:
                    value = overrides[key]
                self._set_widget_value(widget, value, key)

        disabled_det = set(data.get("disabled_detectors", []) or [])
        for name, cb in self._detector_boxes.items():
            cb.setChecked(name not in disabled_det)

        disabled_contra = set(data.get("disabled_contradictions", []) or [])
        for name, cb in self._contradiction_boxes.items():
            cb.setChecked(name not in disabled_contra)

    def _save_overrides(self, values: dict) -> None:
        """Дописать overrides в store. Мердж с тем, что уже сохранено."""
        if self._store is None:
            return
        current = self._store.load()
        merged = dict(current.get("overrides", {}))
        merged.update(values)
        self._store.save_partial(overrides=merged)

    def _save_disabled_detectors(self, disabled) -> None:
        if self._store is None:
            return
        self._store.save_partial(disabled_detectors=set(disabled))

    def _save_disabled_contradictions(self, disabled) -> None:
        if self._store is None:
            return
        self._store.save_partial(disabled_contradictions=set(disabled))

    def _set_widget_value(self, widget, value, key: str) -> None:
        """Записать значение в виджет с учётом его типа и семантики поля."""
        if isinstance(widget, QSpinBox):
            widget.setValue(int(value))
        elif isinstance(widget, QDoubleSpinBox):
            widget.setValue(float(value))
        elif isinstance(widget, QCheckBox):
            widget.setChecked(bool(value))
        elif isinstance(widget, QLineEdit):
            widget.setText(str(value))
        elif isinstance(widget, QPlainTextEdit):
            if key == "private_networks" and isinstance(value, (tuple, list)):
                widget.setPlainText("\n".join(str(x) for x in value))
            elif _is_port_key(key) and isinstance(value, (set, frozenset, list, tuple)):
                widget.setPlainText(_format_ports(value))
            elif isinstance(value, (set, frozenset, list, tuple)):
                widget.setPlainText(_format_lines(value))
            else:
                widget.setPlainText(str(value))


_PORT_TEXT_KEYS = {
    "suspicious_ports",
    "port_scan_excluded_ports",
    "dc_service_ports",
    "lateral_movement_ports",
    "beaconing_mail_polling_ports",
    "brute_force_skip_tls_ports",
}


def _is_port_key(key: str) -> bool:
    if key in _PORT_TEXT_KEYS:
        return True
    return "ports" in key
