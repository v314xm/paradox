"""
HighlightsPanel — топ-3 интересного из отчёта.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


class HighlightsPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("""
            HighlightsPanel {
                background: #282a36;
                border: 1px solid #3a3d4d;
                border-radius: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        title = QLabel("Что привлекло внимание")
        title.setStyleSheet(
            "color: #e0e0e0; font-size: 14px; font-weight: 600;"
        )
        layout.addWidget(title)

        self._body = QLabel("—")
        self._body.setWordWrap(True)
        self._body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._body.setStyleSheet("color: #e0e0e0; font-size: 13px;")
        layout.addWidget(self._body)

    def update_report(self, report: dict) -> None:
        if not report:
            return
        http = report.get("http", {}) or {}
        flows = report.get("flows", {}) or {}
        entities = report.get("entities", {}) or {}

        lines: list[str] = []

        for u in (http.get("top_uris") or [])[:3]:
            method = u.get("method", "?")
            uri = u.get("uri", "?")
            host = u.get("host", "?")
            lines.append(f"• <b>{method}</b> <code>{uri}</code> → <code>{host}</code>")

        for fl in (flows.get("top_by_bytes") or [])[:2]:
            src = fl.get("src_ip", "?")
            dst = fl.get("dst_ip", "?")
            port = fl.get("dst_port", "?")
            b = _fmt_bytes(fl.get("bytes", 0))
            direction = fl.get("direction", "?")
            lines.append(
                f"• flow <code>{src}</code> → <code>{dst}:{port}</code> "
                f"({b}, {direction})"
            )

        for e in (entities.get("external", []) or [])[:2]:
            ip = e.get("ip", "?")
            roles = ", ".join(e.get("roles", []) or []) or "—"
            lines.append(f"• external <code>{ip}</code> ({roles})")

        if not lines:
            self._body.setText(
                "<i style='color:#a0a0b0;'>Нечего выделить — "
                "только стандартный трафик.</i>"
            )
        else:
            self._body.setText("<br>".join(lines))

# AUTO-COMPACTED-HIGHLIGHTS
