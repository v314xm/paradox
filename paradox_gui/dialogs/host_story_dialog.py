"""Диалоговое окно истории хоста (таймлайн)."""
from datetime import datetime

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)


class HostStoryDialog(QDialog):
    def __init__(self, ip: str, story: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"История хоста: {ip}")
        self.resize(700, 600)
        self._build_ui(story)

    def _build_ui(self, story: dict):
        layout = QVBoxLayout(self)

        browser = QTextBrowser()
        browser.setOpenExternalLinks(False)

        events = story.get("events", [])
        summary = story.get("summary", {})

        html = f"<h2>Хронология для {story.get('target_ip', '?')}</h2>"
        html += f"<p><b>Всего событий:</b> {summary.get('total_events', 0)} "
        html += f"| <b>Находок:</b> {summary.get('findings_count', 0)} "
        html += f"| <b>Потоков:</b> {summary.get('flows_count', 0)}</p><hr>"

        if not events:
            html += "<p style='color:#a0a0b0;'>Событий для этого IP не найдено.</p>"
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
                    src = f"{d.get('src_ip')}:{d.get('src_port', '')}"
                    dst = f"{d.get('dst_ip')}:{d.get('dst_port', '')}"
                    byt = d.get('bytes', 0)
                    html += f"<li><b>[{time_str}]</b> Поток: {src} &rarr; {dst} ({byt} байт)</li>"
                elif ev["type"] == "finding":
                    d = ev["data"]
                    ftype = d.get('type', '?')
                    val = d.get('value', '')
                    html += f"<li><b>[{time_str}]</b> <span style='color:#ff7777;'>Сработка: {ftype} ({val})</span></li>"
            html += "</ul>"

        browser.setHtml(html)
        layout.addWidget(browser)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_close = QPushButton("Закрыть")
        btn_close.setObjectName("primary")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)
