"""Вкладка «Настройки» — 11 секций с сайдбаром.

Секции соответствуют Config ядра. Реализованы: Пороги, Детекторы,
Противоречия, Brute force, Сеть, Производительность, Allowlist, DGA,
Threat Intel, Отчёты, Плагины, Общие.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.field_help import (
    get_field_help,
)
from paradox_gui.i18n import (
    tr,
)
from paradox_gui.profiles import (
    ALL_PROFILES,
    DEFAULT_PROFILE_KEY,
    get_profile,
)
from paradox_gui.secrets_store import SecretsStore
from paradox_gui.settings_rehydrate import rehydrate
from paradox_gui.settings_store import SettingsStore
from paradox_gui.views.settings.builders import BuildersMixin
from paradox_gui.views.settings.constants import (
    _SECTIONS,
)
from paradox_gui.views.settings.pages.allowlist import AllowlistPageMixin
from paradox_gui.views.settings.pages.brute_force import BruteForcePageMixin
from paradox_gui.views.settings.pages.contradictions import ContradictionsPageMixin
from paradox_gui.views.settings.pages.detectors import DetectorsPageMixin
from paradox_gui.views.settings.pages.dga import DgaPageMixin
from paradox_gui.views.settings.pages.general import GeneralPageMixin
from paradox_gui.views.settings.pages.network import NetworkPageMixin
from paradox_gui.views.settings.pages.performance import PerformancePageMixin
from paradox_gui.views.settings.pages.plugins import PluginsPageMixin
from paradox_gui.views.settings.pages.reports import ReportsPageMixin
from paradox_gui.views.settings.pages.threatintel import ThreatIntelPageMixin
from paradox_gui.views.settings.pages.thresholds import ThresholdsPageMixin
from paradox_gui.views.settings.pages.yara import YaraPageMixin
from paradox_gui.views.settings.parsers import (
    _format_lines,
    _format_ports,
    _is_port_key,
    _parse_lines,
    _parse_ports,
)
from paradox_gui.widgets.editable_list import (
    EditableListWidget,
)


class SettingsView(
    BuildersMixin,
    GeneralPageMixin,
    ThresholdsPageMixin,
    BruteForcePageMixin,
    NetworkPageMixin,
    PerformancePageMixin,
    AllowlistPageMixin,
    DgaPageMixin,
    ReportsPageMixin,
    PluginsPageMixin,
    YaraPageMixin,
    ThreatIntelPageMixin,
    DetectorsPageMixin,
    ContradictionsPageMixin,
    QWidget,
):
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
        self._status_timer = None
        self._build_ui()
        self._apply_help_tooltips()
        self.load_from_store()
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
        self._search_line.setObjectName("searchField")
        self._search_line.setPlaceholderText(
            tr("settings.search.placeholder")
        )
        self._search_line.setClearButtonEnabled(True)
        self._search_line.setToolTip(tr("settings.search.tooltip"))
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
        self._status_label.setObjectName("statusLine")
        self._status_label.setContentsMargins(12, 4, 12, 4)
        outer.addWidget(self._status_label)

        self._sidebar.currentRowChanged.connect(self._stack.setCurrentIndex)
        self._sidebar.setCurrentRow(0)


    def _build_sidebar(self) -> QListWidget:
        w = QListWidget()
        w.setObjectName("settingsSidebar")
        w.setFixedWidth(200)
        for key, _label in _SECTIONS:
            item = QListWidgetItem(tr(f"settings.section.{key}"))
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
            elif key == "plugins":
                self._stack.addWidget(self._build_plugins_page())
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

        body = tr(f"settings.placeholder.{key}")
        if body == f"settings.placeholder.{key}":
            body = tr("settings.placeholder.fallback")
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
        for group_name in self._INPUT_GROUPS:
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


    _INPUT_GROUPS = (
        "_threshold_inputs", "_brute_inputs", "_network_inputs",
        "_perf_inputs", "_allowlist_inputs", "_dga_inputs",
        "_reports_inputs", "_plugins_inputs", "_ti_inputs", "_yara_inputs",
    )


    def _notify_status(self, msg: str, level: str = "info",
                       timeout_ms: int = 4000) -> None:
        label = getattr(self, "_status_label", None)
        if label is None:
            return
        label.setProperty("level", level)
        label.style().unpolish(label)
        label.style().polish(label)
        label.setText(msg)

        from PySide6.QtCore import QTimer

        # Останавливаем предыдущий таймер: иначе старое сообщение
        # сотрёт новое на своём сроке.
        if self._status_timer is not None:
            self._status_timer.stop()

        def _clear():
            try:
                label.setText("")
            except RuntimeError:
                pass

        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.timeout.connect(_clear)
        self._status_timer.start(timeout_ms)


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
                elif isinstance(widget, QLineEdit) or isinstance(widget, (QPlainTextEdit, EditableListWidget)):
                    widget.textChanged.connect(self._check_modified)


    def _check_modified(self, *args) -> None:
        # Кэшируем Config(): _validate() прогоняет таблицу правил —
        # дорого дёргать на каждое нажатие клавиши.
        if getattr(self, "_defaults", None) is None:
            try:
                from paradox.config import Config
                self._defaults = Config()
            except Exception:
                self._defaults = None
        for group_name in self._INPUT_GROUPS:
            group = getattr(self, group_name, None)
            if not isinstance(group, dict):
                continue
            for key, widget in group.items():
                self._refresh_widget_style(widget, key)


    def _refresh_widget_style(self, widget, key: str) -> None:
        """Совместить modified (цвет текста) и search (фон)."""
        modified = False
        if self._defaults is not None:
            default = getattr(self._defaults, key, None)
            if default is not None:
                try:
                    modified = self._widget_differs(widget, default)
                except Exception:
                    pass
        search_hit = bool(
            self._search_text and self._is_search_match(widget, key)
        )
        for prop, value in (("modified", modified), ("searchHit", search_hit)):
            if widget.property(prop) != value:
                widget.setProperty(prop, value)
                widget.style().unpolish(widget)
                widget.style().polish(widget)


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
        msg = tr("settings.search.found", count=count)
        if hint is not None:
            hint.setText(msg)
        self._notify_status(msg)


    @staticmethod
    def _widget_differs(widget, default) -> bool:
        from PySide6.QtWidgets import (
            QCheckBox,
            QDoubleSpinBox,
            QLineEdit,
            QPlainTextEdit,
            QSpinBox,
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


    def _build_profile_row(self):
        from PySide6.QtWidgets import QHBoxLayout, QLabel

        row = QHBoxLayout()
        row.setSpacing(8)

        row.addWidget(QLabel(tr("settings.profile.label")))
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

        apply_btn = QPushButton(tr("settings.profile.apply"))
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
                tr(
                    "settings.header.params",
                    params=n_ov,
                    disabled=n_dd,
                    rules=n_dc,
                )
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
            from paradox.config import Config
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


    def load_from_store(self) -> None:
        """Накатить сохранённые настройки поверх дефолтов при старте."""
        if self._store is None:
            return
        data = self._store.load()
        overrides = data.get("overrides", {})
        if not isinstance(overrides, dict):
            overrides = {}

        try:
            from paradox.config import Config
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
            self._plugins_inputs,
            self._ti_inputs,
            self._yara_inputs,
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
            widget.setText("" if value is None else str(value))
        elif isinstance(widget, QPlainTextEdit):
            if key == "private_networks" and isinstance(value, (tuple, list)):
                widget.setPlainText("\n".join(str(x) for x in value))
            elif _is_port_key(key) and isinstance(value, (set, frozenset, list, tuple)):
                widget.setPlainText(_format_ports(value))
            elif isinstance(value, (set, frozenset, list, tuple)):
                widget.setPlainText(_format_lines(value))
            else:
                widget.setPlainText(str(value))
