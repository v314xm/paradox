"""
ObservationsPanel — что видел инструмент.

Показывает сводку по HTTP/DNS/flows/entities, даже если findings = 0.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout

from paradox_gui.i18n import tr


class _MetricRow(QFrame):
    def __init__(self, label: str, kind: str):
        super().__init__()
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
        layout.addWidget(self._label)

        self._value = QLabel("—")
        self._value.setObjectName("metricValue")
        self._value.setTextInteractionFlags(Qt.TextSelectableByMouse)
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


class ObservationsPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("obsPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        title = QLabel(tr("obs.title"))
        title.setObjectName("panelTitle")
        layout.addWidget(title)

        self._row_http = _MetricRow("HTTP", "http")
        self._row_dns = _MetricRow("DNS", "dns")
        self._row_flows = _MetricRow("Flows", "flow")
        self._row_hosts = _MetricRow("Hosts", "hosts")
        self._row_tcp = _MetricRow("TCP", "tcp")
        self._row_carved = _MetricRow("Carved", "carved")
        for r in (self._row_http, self._row_dns, self._row_flows,
                  self._row_hosts, self._row_tcp, self._row_carved):
            layout.addWidget(r)

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
            f"{uh} host · {uu} URI · {um} method · {ua} UA",
            empty=(uh == 0 and uu == 0),
        )

        uq = summary.get("unique_dns_queries", 0)
        nx = summary.get("nxdomain_count", 0)
        if uq == 0 and nx == 0:
            self._row_dns.set_value(tr("obs.dns.none"))
        else:
            self._row_dns.set_value(
                tr("obs.dns.count", count=uq, nx=nx)
            )

        total = summary.get("flows", 0)
        self._row_flows.set_value(
            tr("obs.flows_total", count=total), empty=(total == 0)
        )

        n_int = len(entities.get("internal", []) or [])
        n_ext = len(entities.get("external", []) or [])
        self._row_hosts.set_value(
            tr("obs.hosts", internal=n_int, external=n_ext),
            empty=(n_int == 0 and n_ext == 0),
        )

        tcp_s = summary.get("tcp_streams", 0)
        trunc = summary.get("tcp_streams_truncated", 0)
        if total == 0:
            self._row_tcp.set_value("—")
        else:
            extra = (
                tr("obs.tcp_truncated", count=trunc) if trunc else ""
            )
            self._row_tcp.set_value(
                tr("obs.tcp", count=tcp_s, truncated=extra)
            )

        n_carved = summary.get("carved_files", 0)
        self._row_carved.set_value(
            "—" if n_carved == 0 else tr("obs.carved", count=n_carved)
        )

    def clear(self) -> None:
        """Сбросить панель перед новым прогоном."""
        for row in (
            self._row_http, self._row_dns, self._row_flows,
            self._row_hosts, self._row_tcp, self._row_carved,
        ):
            row.set_value("—")

# AUTO-COMPACTED-OBSERVATIONS
