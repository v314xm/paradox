"""
ObservationsPanel — что видел инструмент.

Показывает сводку по HTTP/DNS/flows/entities, даже если findings = 0.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout


class _MetricRow(QFrame):
    def __init__(self, label: str):
        super().__init__()
        self.setStyleSheet("QFrame { background: transparent; }")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 1, 0, 1)
        layout.setSpacing(8)

        self._label = QLabel(label)
        self._label.setFixedWidth(70)
        self._label.setStyleSheet(
            "color: #a0a0b0; font-size: 12px; font-weight: 600;"
        )
        layout.addWidget(self._label)

        self._value = QLabel("—")
        self._value.setStyleSheet("color: #e0e0e0; font-size: 13px;")
        self._value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self._value, 1)

    def set_value(self, text: str) -> None:
        self._value.setText(text)


class ObservationsPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("""
            ObservationsPanel {
                background: #282a36;
                border: 1px solid #3a3d4d;
                border-radius: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        title = QLabel("Что видел инструмент")
        title.setStyleSheet(
            "color: #e0e0e0; font-size: 14px; font-weight: 600;"
        )
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
