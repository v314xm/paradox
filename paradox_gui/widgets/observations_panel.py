"""
ObservationsPanel — что видел инструмент.

Показывает сводку по HTTP/DNS/flows/entities, даже если findings = 0.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout

from paradox_gui.i18n import tr


class _MetricRow(QFrame):
    def __init__(self, label: str):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(10)

        self._label = QLabel(label)
        self._label.setObjectName("metricLabel")
        self._label.setFixedWidth(64)
        layout.addWidget(self._label)

        self._value = QLabel("—")
        self._value.setObjectName("metricValue")
        self._value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self._value, 1)

    def set_value(self, text: str) -> None:
        self._value.setText(text)


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

        self._row_http = _MetricRow("HTTP")
        self._row_dns = _MetricRow("DNS")
        self._row_flows = _MetricRow("Flows")
        self._row_hosts = _MetricRow("Hosts")
        self._row_tcp = _MetricRow("TCP")
        self._row_carved = _MetricRow("Carved")
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
            f"{uh} host · {uu} URI · {um} method · {ua} UA"
        )

        uq = summary.get("unique_dns_queries", 0)
        nx = summary.get("nxdomain_count", 0)
        if uq == 0 and nx == 0:
            self._row_dns.set_value("— запросов не было")
        else:
            self._row_dns.set_value(f"{uq} запросов · {nx} NXDOMAIN")

        total = summary.get("flows", 0)
        self._row_flows.set_value(f"{total} total")

        n_int = len(entities.get("internal", []) or [])
        n_ext = len(entities.get("external", []) or [])
        self._row_hosts.set_value(f"{n_int} internal · {n_ext} external")

        tcp_s = summary.get("tcp_streams", 0)
        trunc = summary.get("tcp_streams_truncated", 0)
        if total == 0:
            self._row_tcp.set_value("—")
        else:
            extra = f" · {trunc} truncated" if trunc else ""
            self._row_tcp.set_value(f"{tcp_s} streams{extra}")

        n_carved = summary.get("carved_files", 0)
        self._row_carved.set_value(
            "—" if n_carved == 0 else f"{n_carved} файлов"
        )

# AUTO-COMPACTED-OBSERVATIONS
