"""Диалоговое окно истории хоста (таймлайн)."""
from datetime import datetime
from html import escape

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QTextBrowser,
    QVBoxLayout,
)

from paradox_gui.i18n import tr
from paradox_gui.theme import MONO_FAMILY, PALETTE

_DOC_CSS = (
    "<style>"
    f"h2{{color:{PALETTE['accent']};}}"
    f".muted{{color:{PALETTE['text_muted']};}}"
    f".danger{{color:{PALETTE['danger']};}}"
    f".mono{{font-family:{MONO_FAMILY};}}"
    "</style>"
)


class HostStoryDialog(QDialog):
    def __init__(self, ip: str, story: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("hostStoryDialog")
        self.setWindowTitle(tr("story.title", ip=ip))
        self.resize(760, 620)
        self.setMinimumSize(600, 460)
        self._build_ui(story)

    def _build_ui(self, story: dict):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        browser = QTextBrowser()
        browser.setObjectName("storyBrowser")
        browser.setOpenExternalLinks(False)
        browser.document().setDefaultStyleSheet(_DOC_CSS)

        events = story.get("events", [])
        summary = story.get("summary", {})

        html = _DOC_CSS
        html += (
            f"<h2>{tr('story.timeline', ip=escape(str(story.get('target_ip', '?'))))}</h2>"
        )
        html += f"<p><b>{tr('story.total')}</b> {summary.get('total_events', 0)} "
        html += f"| <b>{tr('story.findings')}</b> {summary.get('findings_count', 0)} "
        html += f"| <b>{tr('story.flows')}</b> {summary.get('flows_count', 0)}</p><hr>"

        if not events:
            html += f"<p class='muted'>{tr('story.empty')}</p>"
        else:
            html += "<ul style='line-height: 1.6;'>"
            for ev in events:
                ts = ev.get("ts")
                time_str = "??:??:??"
                if ts:
                    try:
                        time_str = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
                    except (OSError, ValueError):
                        time_str = str(ts)

                if ev["type"] == "flow":
                    d = ev["data"]
                    src = escape(
                        f"{d.get('src_ip')}:{d.get('src_port', '')}"
                    )
                    dst = escape(
                        f"{d.get('dst_ip')}:{d.get('dst_port', '')}"
                    )
                    byt = d.get('bytes', 0)
                    html += (
                        f"<li><b class='mono'>[{time_str}]</b> "
                        f"{tr('story.flow', src=src, dst=dst, nbytes=byt)}</li>"
                    )
                elif ev["type"] == "finding":
                    d = ev["data"]
                    ftype = escape(str(d.get('type', '?')))
                    val = escape(str(d.get('value', '')))
                    html += (
                        f"<li><b class='mono'>[{time_str}]</b> "
                        f"<span class='danger'>"
                        f"{tr('story.finding', ftype=ftype, value=val)}"
                        f"</span></li>"
                    )
            html += "</ul>"

        browser.setHtml(html)
        layout.addWidget(browser)

        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        box.setObjectName("dialogButtons")
        close = box.button(QDialogButtonBox.StandardButton.Close)
        close.setText(tr("story.close"))
        close.setDefault(True)
        box.rejected.connect(self.accept)
        layout.addWidget(box)
