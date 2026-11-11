"""
ObservationsPanel — что видел инструмент.

Левая колонка — счётчики разбора: HTTP/DNS/flows/entities, трафик,
протоколы, TLS и ошибки разбора. Правая — плитки итога триажа:
находки и противоречия с разбивкой по severity, вырезанные файлы и
сертификаты. Время прогона сюда не входит — оно живёт в «Истории».
"""
from __future__ import annotations

from collections import Counter

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.formatting import fmt_bytes as _fmt_bytes
from paradox_gui.formatting import fmt_count as _fmt_count
from paradox_gui.i18n import tr

#: Подписи прикладных протоколов для разреза summary.protocols.by_l7.
_L7_LABELS = {
    "http": "HTTP",
    "tls": "TLS",
    "dns": "DNS",
    "smb": "SMB",
    "ldap": "LDAP",
    "kerberos": "Kerberos",
    "ssh": "SSH",
    "smtp": "SMTP",
    "dhcp": "DHCP",
    "netbios": "NetBIOS",
    "nbns": "NBNS",
    "ntp": "NTP",
    "ssdp": "SSDP",
    "icmp": "ICMP",
}

#: Порядок severity в подписи плитки.
_SEVERITIES = ("critical", "high", "medium", "low", "info")


class _MetricRow(QFrame):
    def __init__(self, label: str, kind: str, tooltip: str):
        super().__init__()
        self.setToolTip(tooltip)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(6)

        # Цветная точка связывает строку с категорией хайлайта,
        # чтобы панели читались как один набор, а не как два списка.
        self._dot = QLabel()
        self._dot.setObjectName("metricDot")
        self._dot.setProperty("kind", kind)
        self._dot.setFixedSize(6, 6)
        layout.addWidget(self._dot, 0, Qt.AlignmentFlag.AlignVCenter)

        self._label = QLabel(label)
        self._label.setObjectName("metricLabel")
        self._label.setToolTip(tooltip)
        layout.addWidget(self._label)

        self._value = QLabel("—")
        self._value.setObjectName("metricValue")
        self._value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._value.setToolTip(tooltip)
        layout.addWidget(self._value, 1)

    def set_value(self, text: str, empty: bool = False) -> None:
        self._value.setText(text)
        # «—» и нулевые счётчики — это отсутствие данных, а не метрика:
        # не даём им светиться тем же цветом, что и реальные числа.
        empty = empty or text.startswith("—")
        if self._value.property("empty") != empty:
            self._value.setProperty("empty", empty)
            self._value.style().unpolish(self._value)
            self._value.style().polish(self._value)


class _KpiTile(QFrame):
    """Кликабельная плитка итога в общем стиле SummaryTile.

    Клик уводит в детали: таблицу находок, противоречия, файлы или
    сертификаты — плитка это ссылка, а не просто число.
    """

    clicked = Signal()

    def __init__(self, caption_key: str):
        super().__init__()
        self.setObjectName("summaryTile")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("hasContra", False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.value = QLabel("—")
        self.value.setObjectName("summaryValue")
        self.value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value.setProperty("empty", True)
        self.value.setProperty("hasContra", False)

        self.caption = QLabel(tr(caption_key))
        self.caption.setObjectName("metricLabel")
        self.caption.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.sub = QLabel("")
        self.sub.setObjectName("hint")
        self.sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sub.setWordWrap(True)

        layout.addWidget(self.value)
        layout.addWidget(self.caption)
        layout.addWidget(self.sub)

    def set_value(
        self, value: str, sub: str = "", *,
        empty: bool = False, contra: bool = False,
    ) -> None:
        self.value.setText(value)
        self.sub.setText(sub)
        self.sub.setVisible(bool(sub))
        self._set_flag(self.value, "empty", empty)
        self._set_flag(self.value, "hasContra", contra)
        self._set_flag(self, "hasContra", contra)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 (Qt API)
        if (
            event.button() == Qt.MouseButton.LeftButton
            and self.rect().contains(event.position().toPoint())
        ):
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    @staticmethod
    def _set_flag(widget: QWidget, name: str, value: bool) -> None:
        if widget.property(name) == value:
            return
        widget.setProperty(name, value)
        widget.style().unpolish(widget)
        widget.style().polish(widget)


class ObservationsPanel(QFrame):
    findings_requested = Signal()
    contradictions_requested = Signal()
    files_requested = Signal()
    certificates_requested = Signal()

    _ROWS = (
        "http", "dns", "flows", "hosts", "tcp", "carved",
        "traffic", "protocols", "tls", "diag",
    )

    def __init__(self):
        super().__init__()
        self.setObjectName("obsPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        title = QLabel(tr("obs.title"))
        title.setObjectName("panelTitle")
        layout.addWidget(title)

        subtitle = QLabel(tr("obs.subtitle"))
        subtitle.setObjectName("hint")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        body = QHBoxLayout()
        body.setContentsMargins(0, 4, 0, 0)
        body.setSpacing(16)

        rows = QVBoxLayout()
        rows.setContentsMargins(0, 0, 0, 0)
        rows.setSpacing(2)

        self._row_http = self._make_row("http", "http", "http")
        self._row_dns = self._make_row("dns", "dns", "dns")
        self._row_flows = self._make_row("flows", "flows", "flow")
        self._row_hosts = self._make_row("hosts", "hosts", "hosts")
        self._row_tcp = self._make_row("tcp", "tcp", "tcp")
        self._row_carved = self._make_row("carved", "carved", "carved")
        self._row_traffic = self._make_row("traffic", "traffic", "traffic")
        self._row_protocols = self._make_row(
            "protocols", "protocols", "proto",
        )
        self._row_tls = self._make_row("tls", "tls", "tls")
        self._row_diag = self._make_row("diag", "diag", "diag")
        for key in self._ROWS:
            rows.addWidget(getattr(self, f"_row_{key}"))
        rows.addStretch(1)
        body.addLayout(rows, 1)

        body.addWidget(self._build_kpi_box(), 1)
        layout.addLayout(body)

    def _build_kpi_box(self) -> QWidget:
        box = QWidget()
        box.setObjectName("kpiBox")

        column = QVBoxLayout(box)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(6)

        title = QLabel(tr("kpi.title"))
        title.setObjectName("panelTitle")
        column.addWidget(title)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(8)

        self._kpi_findings = _KpiTile("kpi.findings")
        self._kpi_contra = _KpiTile("kpi.contradictions")
        self._kpi_files = _KpiTile("kpi.files")
        self._kpi_tls = _KpiTile("kpi.tls")

        self._kpi_findings.clicked.connect(self.findings_requested)
        self._kpi_contra.clicked.connect(self.contradictions_requested)
        self._kpi_files.clicked.connect(self.files_requested)
        self._kpi_tls.clicked.connect(self.certificates_requested)

        self._kpi_findings.setToolTip(tr("kpi.hint.findings"))
        self._kpi_contra.setToolTip(tr("kpi.hint.contradictions"))
        self._kpi_files.setToolTip(tr("kpi.hint.files"))
        self._kpi_tls.setToolTip(tr("kpi.hint.tls"))

        for index, tile in enumerate((
            self._kpi_findings, self._kpi_contra,
            self._kpi_files, self._kpi_tls,
        )):
            row, column_index = divmod(index, 2)
            grid.addWidget(tile, row, column_index)
        column.addLayout(grid)
        column.addStretch(1)
        return box

    @staticmethod
    def _make_row(key: str, label_key: str, kind: str) -> _MetricRow:
        return _MetricRow(
            tr(f"obs.row.{label_key}"),
            kind,
            tr(f"obs.hint.{key}"),
        )

    def update_report(self, report: dict) -> None:
        if not report:
            return
        summary = report.get("summary", {}) or {}
        http = report.get("http", {}) or {}
        entities = report.get("entities", {}) or {}

        uh = http.get("unique_hosts", 0)
        uu = http.get("unique_uris", 0)
        um = len(http.get("methods") or [])
        ua = http.get("unique_user_agents", 0)
        self._row_http.set_value(
            tr(
                "obs.http",
                hosts=_fmt_count(uh),
                uris=_fmt_count(uu),
                methods=_fmt_count(um),
                ua=_fmt_count(ua),
            ),
            empty=(uh == 0 and uu == 0),
        )

        uq = summary.get("unique_dns_queries", 0)
        nx = summary.get("nxdomain_count", 0)
        if uq == 0 and nx == 0:
            self._row_dns.set_value(tr("obs.dns.none"))
        else:
            self._row_dns.set_value(
                tr("obs.dns.count", count=_fmt_count(uq), nx=_fmt_count(nx))
            )

        total = int(summary.get("flows", 0) or 0)
        self._row_flows.set_value(
            tr("obs.flows_total", count=_fmt_count(total)),
            empty=(total == 0),
        )

        n_int = len(entities.get("internal", []) or [])
        n_ext = len(entities.get("external", []) or [])
        self._row_hosts.set_value(
            tr(
                "obs.hosts",
                internal=_fmt_count(n_int),
                external=_fmt_count(n_ext),
            ),
            empty=(n_int == 0 and n_ext == 0),
        )

        tcp_s = int(summary.get("tcp_streams", 0) or 0)
        trunc = int(summary.get("tcp_streams_truncated", 0) or 0)
        if total == 0:
            self._row_tcp.set_value("—")
        else:
            extra = (
                tr("obs.tcp_truncated", count=_fmt_count(trunc))
                if trunc else ""
            )
            self._row_tcp.set_value(
                tr("obs.tcp", count=_fmt_count(tcp_s), truncated=extra)
            )

        n_carved = int(summary.get("carved_files", 0) or 0)
        self._row_carved.set_value(
            "—" if n_carved == 0
            else tr("obs.carved", count=_fmt_count(n_carved))
        )

        self._update_traffic(summary)
        self._update_protocols(summary)
        self._update_tls(summary)
        self._update_diag(summary)
        self._update_kpis(report)

    # ------------------------------------------------------------------ ряды

    def _update_traffic(self, summary: dict) -> None:
        up = int(summary.get("uploaded_bytes", 0) or 0)
        down = int(summary.get("downloaded_bytes", 0) or 0)
        internal = int(summary.get("internal_bytes", 0) or 0)
        if not (up or down or internal):
            self._row_traffic.set_value("—")
            return
        text = tr(
            "obs.bytes", up=_fmt_bytes(up), down=_fmt_bytes(down),
        )
        if internal:
            text += tr("obs.bytes_internal", value=_fmt_bytes(internal))
        self._row_traffic.set_value(text)

    def _update_protocols(self, summary: dict) -> None:
        by_l7 = (summary.get("protocols") or {}).get("by_l7") or {}
        # «other» — не протокол, а остаток: показываем его последним,
        # иначе он вытесняет из топ-4 HTTP/TLS/DNS.
        items = sorted(
            by_l7.items(),
            key=lambda kv: (kv[0] == "other", -kv[1], kv[0]),
        )
        if not items:
            self._row_protocols.set_value("—")
            return
        top = items[:4]
        text = " · ".join(
            f"{_L7_LABELS.get(name, name.upper())} {_fmt_count(count)}"
            for name, count in top
        )
        rest = len(items) - len(top)
        if rest:
            text += tr("obs.protocols_more", count=rest)
        self._row_protocols.set_value(text)

    def _update_tls(self, summary: dict) -> None:
        certs = int(summary.get("certificates", 0) or 0)
        decrypted = int(summary.get("tls_decrypted_streams", 0) or 0)
        if not (certs or decrypted):
            self._row_tls.set_value("—")
            return
        self._row_tls.set_value(tr(
            "obs.tls",
            certs=_fmt_count(certs),
            decrypted=_fmt_count(decrypted),
        ))

    def _update_diag(self, summary: dict) -> None:
        extractor_errors = summary.get("extractor_errors") or {}
        errors = sum(int(v or 0) for v in extractor_errors.values())
        for key in (
            "tls_cert_parse_errors", "smb2_parse_errors",
            "ldap_parse_errors", "h2_parse_errors", "tls_decrypt_errors",
        ):
            errors += int(summary.get(key, 0) or 0)
        no_key = int(summary.get("tls_streams_without_keylog", 0) or 0)
        truncated = int(summary.get("tcp_streams_truncated", 0) or 0)

        parts = []
        if errors:
            parts.append(tr("obs.diag.errors", count=_fmt_count(errors)))
        if no_key:
            parts.append(tr("obs.diag.nokey", count=_fmt_count(no_key)))
        if truncated:
            parts.append(tr("obs.diag.truncated", count=_fmt_count(truncated)))
        self._row_diag.set_value(" · ".join(parts) if parts else "—")

    # ------------------------------------------------------------------ плитки

    def _update_kpis(self, report: dict) -> None:
        findings = [
            f for f in (report.get("findings") or [])
            if isinstance(f, dict)
        ]
        contradictions = [
            c for c in (report.get("contradictions") or [])
            if isinstance(c, dict)
        ]
        self._kpi_findings.set_value(
            _fmt_count(len(findings)),
            _severity_line(findings),
            empty=not findings,
        )
        self._kpi_contra.set_value(
            _fmt_count(len(contradictions)),
            _severity_line(contradictions),
            empty=not contradictions,
            contra=bool(contradictions),
        )

        carved = report.get("carved_files") or {}
        files = [
            f for f in (carved.get("files") or [])
            if isinstance(f, dict)
        ]
        total = int(carved.get("total") or len(files))
        self._kpi_files.set_value(
            _fmt_count(total),
            _ext_line(files),
            empty=(total == 0),
        )

        summary = report.get("summary", {}) or {}
        certs = int(summary.get("certificates", 0) or 0)
        decrypted = int(summary.get("tls_decrypted_streams", 0) or 0)
        self._kpi_tls.set_value(
            _fmt_count(certs),
            tr("kpi.tls.decrypted", count=_fmt_count(decrypted))
            if decrypted else "",
            empty=(certs == 0 and decrypted == 0),
        )

    def clear(self) -> None:
        """Сбросить панель перед новым прогоном."""
        for key in self._ROWS:
            getattr(self, f"_row_{key}").set_value("—")
        for tile in (
            self._kpi_findings, self._kpi_contra,
            self._kpi_files, self._kpi_tls,
        ):
            tile.set_value("—", "", empty=True)


def _severity_line(items: list[dict]) -> str:
    """«крит 1 · выс 3 · сред 2» — только те severity, что есть."""
    counts = Counter(
        str(item.get("severity") or "").lower() for item in items
    )
    parts = [
        f"{tr(f'kpi.sev.{severity}')} {counts[severity]}"
        for severity in _SEVERITIES
        if counts.get(severity)
    ]
    return " · ".join(parts)


def _ext_line(files: list[dict]) -> str:
    """«php 2 · exe 1» — что именно вырезано."""
    counts = Counter(
        str(f.get("ext") or "?").lower() for f in files
    )
    return " · ".join(
        f"{ext} {count}" for ext, count in counts.most_common(3)
    )
