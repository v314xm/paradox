"""Вкладка «Настройки» — 11 секций с сайдбаром.

Секции соответствуют Config ядра. Пока реализованы: Пороги, Детекторы,
Противоречия. Остальные — заглушки.
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
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
)

_CONTRADICTIONS = (
    ("VictimMakesAttackRule",   "victim_makes_attack (PIVOT) — critical"),
    ("MacIpConflictRule",       "mac_ip_conflict (ARP-spoof) — critical"),
    ("SniHostMismatchRule",     "sni_host_mismatch (fronting) — high"),
    ("Ja3UaMismatchRule",       "ja3_ua_mismatch (UA spoof) — high"),
    ("ReverseAsymmetryRule",    "reverse_asymmetry (exfil) — medium"),
    ("PortServiceMismatchRule", "port_service_mismatch (tunnel) — high"),
    ("DirectIpNoDnsRule",       "direct_ip_no_dns (hardcoded) — medium"),
)


class SettingsView(QWidget):
    thresholds_applied = Signal(object)
    detectors_applied = Signal(object)
    contradictions_applied = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._sidebar = self._build_sidebar()
        layout.addWidget(self._sidebar)

        self._stack = QStackedWidget()
        self._build_pages()
        layout.addWidget(self._stack, stretch=1)

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
            else:
                self._stack.addWidget(self._placeholder_page(label))

    def _placeholder_page(self, title: str) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(24, 24, 24, 24)
        v.setSpacing(12)
        h = QLabel(title)
        h.setObjectName("h1")
        v.addWidget(h)
        hint = QLabel("Секция в разработке.")
        hint.setObjectName("muted")
        v.addWidget(hint)
        v.addStretch(1)
        return w

    def goto(self, key: str) -> None:
        for i in range(self._sidebar.count()):
            item = self._sidebar.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == key:
                self._sidebar.setCurrentRow(i)
                return

    # =========================================================================
    # СЕКЦИЯ: Пороги
    # =========================================================================

    def _build_thresholds_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        title = QLabel("Пороги")
        title.setObjectName("h1")
        outer.addWidget(title)

        subtitle = QLabel(
            "Пороги детекторов из Config ядра. Изменения применяются "
            "к следующему прогону."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        form_host = QWidget()
        form = QFormLayout(form_host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._threshold_inputs: dict[str, object] = {}

        self._add_int_row(form, "dga_min_label_length", "DGA: минимальная длина label")
        self._add_float_row(form, "dga_entropy_threshold", "DGA: порог энтропии", step=0.1)
        self._add_int_row(form, "nxdomain_burst_threshold", "NXDOMAIN burst")
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

        scroll.setWidget(form_host)
        outer.addWidget(scroll, stretch=1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        reset_btn = QPushButton("Сбросить к default")
        reset_btn.clicked.connect(self._reset_thresholds)
        apply_btn = QPushButton("Применить")
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_thresholds)
        buttons.addWidget(reset_btn)
        buttons.addWidget(apply_btn)
        outer.addLayout(buttons)

        self._load_thresholds()
        return w

    def _add_int_row(self, form, key: str, label: str,
                     lo: int = 0, hi: int = 1_000_000_000) -> None:
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setFixedWidth(160)
        form.addRow(label, sp)
        self._threshold_inputs[key] = sp

    def _add_float_row(self, form, key: str, label: str,
                       step: float = 0.1, lo: float = 0.0,
                       hi: float = 1000.0) -> None:
        sp = QDoubleSpinBox()
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setDecimals(3)
        sp.setFixedWidth(160)
        form.addRow(label, sp)
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
    # СЕКЦИЯ: Детекторы
    # =========================================================================

    def _build_detectors_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        title = QLabel("Детекторы")
        title.setObjectName("h1")
        outer.addWidget(title)

        subtitle = QLabel(
            "Снятая галочка отключает детектор в следующем прогоне. "
            "Порядок совпадает с ядром."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        box_host = QWidget()
        box_layout = QVBoxLayout(box_host)
        box_layout.setContentsMargins(0, 8, 0, 8)
        box_layout.setSpacing(4)

        self._detector_boxes: dict[str, object] = {}
        for name, label in _DETECTORS:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self._detector_boxes[name] = cb
            box_layout.addWidget(cb)
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

        title = QLabel("ContradictionDetector")
        title.setObjectName("h1")
        outer.addWidget(title)

        subtitle = QLabel(
            "Правила проверяют согласованность между слоями данных. "
            "Отключение правила убирает его из следующего прогона."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        box_host = QWidget()
        box_layout = QVBoxLayout(box_host)
        box_layout.setContentsMargins(0, 8, 0, 8)
        box_layout.setSpacing(4)

        self._contradiction_boxes: dict[str, object] = {}
        for name, label in _CONTRADICTIONS:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self._contradiction_boxes[name] = cb
            box_layout.addWidget(cb)
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

    def _set_all_contradictions(self, checked: bool) -> None:
        for cb in self._contradiction_boxes.values():
            cb.setChecked(checked)

    def _apply_contradictions(self) -> None:
        disabled = {
            name for name, cb in self._contradiction_boxes.items()
            if not cb.isChecked()
        }
        self.contradictions_applied.emit(disabled)