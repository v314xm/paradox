"""Вкладка «Настройки» — 11 секций с сайдбаром.

Секции соответствуют Config ядра. Реализованы: Пороги, Детекторы,
Противоречия, Brute force, Сеть, Производительность, Allowlist, DGA,
Threat Intel, Отчёты. Заглушка — только «Общие».
"""
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
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
    thresholds_applied = Signal(object)
    detectors_applied = Signal(object)
    contradictions_applied = Signal(object)
    # Секции Brute force / Сеть / Производительность / Allowlist / DGA /
    # Threat Intel / Отчёты шлют плоский dict {поле Config: значение}.
    # run_view мерджит в общий overrides.
    config_applied = Signal(object)

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
            elif key == "reports":
                self._stack.addWidget(self._build_reports_page())
            elif key == "threatintel":
                self._stack.addWidget(self._build_threatintel_page())
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
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        scroll.setWidget(host)
        return scroll, form

    def _make_header(self, title: str, subtitle: str) -> tuple[QLabel, QLabel]:
        t = QLabel(title)
        t.setObjectName("h1")
        s = QLabel(subtitle)
        s.setObjectName("muted")
        s.setWordWrap(True)
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
    # СЕКЦИЯ: Пороги
    # =========================================================================

    def _build_thresholds_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            "Пороги",
            "Пороги детекторов из Config ядра. Изменения применяются "
            "к следующему прогону.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
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

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_thresholds, self._apply_thresholds))

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

        self._bf_skip_tls = QPlainTextEdit()
        self._bf_skip_tls.setFixedHeight(72)
        form.addRow("HTTP: порты, где brute force не ищем (TLS)", self._bf_skip_tls)
        self._brute_inputs["brute_force_skip_tls_ports"] = self._bf_skip_tls

        self._bf_login_hints = QPlainTextEdit()
        self._bf_login_hints.setFixedHeight(120)
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
        form.addRow(label, sp)
        self._brute_inputs[key] = sp

    def _add_float_row_bf(self, form, key, label, lo, hi, step, decimals):
        sp = QDoubleSpinBox()
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setDecimals(decimals)
        sp.setFixedWidth(160)
        form.addRow(label, sp)
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
            elif isinstance(widget, QPlainTextEdit):
                if isinstance(value, frozenset):
                    if value and isinstance(next(iter(value)), int):
                        widget.setPlainText(_format_ports(value))
                    else:
                        widget.setPlainText(_format_lines(value))

    def _apply_brute_force(self) -> None:
        values: dict = {}
        for key, widget in self._brute_inputs.items():
            if isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QDoubleSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QPlainTextEdit):
                text = widget.toPlainText()
                if "ports" in key or "skip_tls" in key:
                    values[key] = _parse_ports(text)
                else:
                    values[key] = _parse_lines(text)
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
            "Списки портов и префиксов сетей. Элемент — число (порт) "
            "или строка (префикс). Один элемент на строку, # — комментарий.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._network_inputs: dict[str, object] = {}

        self._add_list_row(form, "suspicious_ports",
                           "Подозрительные порты (детектор suspicious_port)")
        self._add_list_row(form, "port_scan_excluded_ports",
                           "Исключения port scan (порты)")
        self._add_list_row(form, "dc_service_ports",
                           "Порты, отличающие domain controller")
        self._add_list_row(form, "lateral_movement_ports",
                           "Порты lateral movement")
        self._add_list_row(form, "beaconing_mail_polling_ports",
                           "Порты mail-polling (POP3/IMAP — не beaconing)")
        self._add_list_row(form, "private_networks",
                           "Префиксы приватных сетей (стр., напр. 10.)",
                           height=140)

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_network, self._apply_network))

        self._load_network()
        return w

    def _add_list_row(self, form, key, label, height=90):
        te = QPlainTextEdit()
        te.setFixedHeight(height)
        form.addRow(label, te)
        self._network_inputs[key] = te

    def _load_network(self) -> None:
        try:
            from pcap_triage.config import Config
        except ImportError:
            return
        cfg = Config()
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
                # private_networks — tuple[str, ...]
                widget.setPlainText("\n".join(value))

    def _apply_network(self) -> None:
        values: dict = {}
        for key, widget in self._network_inputs.items():
            text = widget.toPlainText()
            if key == "private_networks":
                values[key] = tuple(
                    line.strip() for line in text.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
            else:
                values[key] = _parse_ports(text)
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
            "Компромисс память/полнота. Отключение TCP-склейки и карвинга "
            "ускоряет прогон на больших pcap, но теряет часть findings.",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._perf_inputs: dict[str, object] = {}

        self._add_bool_row(form, "tcp_reassembly_enabled",
                           "TCP reassembly (склейка сегментов)")
        self._add_int_row_pf(form, "tcp_reassembly_max_bytes_per_flow",
                             "TCP reassembly: макс. байт на flow",
                             lo=4096, hi=100 * 1024 * 1024)
        self._add_int_row_pf(form, "tcp_reassembly_max_total_bytes",
                             "TCP reassembly: макс. байт всего",
                             lo=1024 * 1024, hi=2000 * 1024 * 1024)
        self._add_bool_row(form, "file_carve_enabled",
                           "File carve: извлекать метаданные payload'ов")
        self._add_bool_row(form, "file_carve_write_body",
                           "File carve: писать тела файлов на диск (осторожно)")
        self._add_int_row_pf(form, "file_carve_min_size",
                             "File carve: мин. размер (байт)",
                             lo=1, hi=1024 * 1024)
        self._add_int_row_pf(form, "file_carve_max_size",
                             "File carve: макс. размер (байт)",
                             lo=1024, hi=500 * 1024 * 1024)
        self._add_int_row_pf(form, "entities_top_n",
                             "Сущности: топ-N по активности",
                             lo=1, hi=10000)
        self._add_int_row_pf(form, "flow_report_top_n",
                             "Flow report: топ-N по байтам",
                             lo=1, hi=100000)

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_performance, self._apply_performance))

        self._load_performance()
        return w

    def _add_bool_row(self, form, key, label):
        cb = QCheckBox()
        form.addRow(label, cb)
        self._perf_inputs[key] = cb

    def _add_int_row_pf(self, form, key, label, lo, hi):
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setFixedWidth(180)
        form.addRow(label, sp)
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
        te = QPlainTextEdit()
        te.setFixedHeight(height)
        form.addRow(label, te)
        self._allowlist_inputs[key] = te

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

        self._dga_allowlist = QPlainTextEdit()
        self._dga_allowlist.setMinimumHeight(300)
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
        # Ограничиваем ширину формы: иначе в полноэкранном окне метки
        # уезжают к центру, а поля теряются справа.
        host.setMaximumWidth(720)
        form = QFormLayout(host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        scroll.setWidget(host)

        self._ti_inputs: dict[str, object] = {}

        # --- Провайдеры (какие вообще используются) ---
        te_prov = QPlainTextEdit()
        te_prov.setFixedHeight(100)
        te_prov.setMaximumWidth(500)
        form.addRow(
            "Провайдеры (shodan_internetdb, abuseipdb, virustotal)",
            te_prov,
        )
        self._ti_inputs["enrichment_enabled_providers"] = te_prov

        # --- API-ключи ---
        # Отдельная визуальная группа: ключи не из Config, а из
        # переменных окружения. Секция явно их не сохраняет на диск —
        # только выставляет в os.environ текущего процесса.
        # >>> THREAT INTEL: ключи API <<<
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
        # >>> /THREAT INTEL: ключи API <<<

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

    def _load_threatintel(self) -> None:
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
            elif isinstance(widget, QPlainTextEdit):
                if isinstance(value, (frozenset, tuple, set, list)):
                    widget.setPlainText(_format_lines(value))

        # Ключи — из окружения, не из Config. Если уже установлены
        # (например, в PowerShell перед запуском) — показываем, чтобы
        # пользователь видел, что работает.
        import os
        self._ti_abuse_key.setText(os.environ.get("ABUSEIPDB_API_KEY", ""))
        self._ti_vt_key.setText(os.environ.get("VIRUSTOTAL_API_KEY", ""))

    def _apply_threatintel(self) -> None:
        # >>> THREAT INTEL: ключи API <<<
        # Ключи не идут в config_applied — они не поля Config.
        # Выставляем в os.environ текущего процесса: ядро читает их
        # через os.environ.get() при первом обращении к провайдеру.
        import os
        abuse = self._ti_abuse_key.text().strip()
        vt = self._ti_vt_key.text().strip()
        if abuse:
            os.environ["ABUSEIPDB_API_KEY"] = abuse
        else:
            os.environ.pop("ABUSEIPDB_API_KEY", None)
        if vt:
            os.environ["VIRUSTOTAL_API_KEY"] = vt
        else:
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
        # >>> /THREAT INTEL: ключи API <<<

        # Остальные поля — обычные, идут в config_applied.
        values: dict = {}
        for key, widget in self._ti_inputs.items():
            if isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QLineEdit):
                if key == "enrichment_cache_path":
                    text = widget.text().strip()
                    if text:
                        try:
                            Path(text).parent.mkdir(parents=True, exist_ok=True)
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
