"""Часть главного окна: export."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QMessageBox,
)

from paradox_gui.i18n import tr


class ExportMixin:
    def _on_export_json(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("dialog.file.save_json.title"),
            self._default_export_name("json"),
            tr("dialog.file.save_json.filter"),
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True),
                encoding="utf-8",
            )
            self._status_text.setText(tr("status.saved", path=path))
        except Exception as e:
            QMessageBox.critical(self, tr("error.save.title"), str(e))


    def _on_export_md(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("dialog.file.save_md.title"),
            self._default_export_name("md"),
            tr("dialog.file.save_md.filter"),
        )
        if not path:
            return
        try:
            from paradox.reporters.markdown_reporter import render_markdown
            Path(path).write_text(render_markdown(report), encoding="utf-8")
            self._status_text.setText(tr("status.saved", path=path))
        except Exception as e:
            QMessageBox.critical(self, tr("error.save.title"), str(e))


    def _on_export_conn(self) -> None:
        report = self.run_view.last_report()
        if not report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("dialog.file.save_conn.title"),
            self._default_export_name("log"),
            tr("dialog.file.save_conn.filter"),
        )
        if not path:
            return
        try:
            flows = report.get("flows", {})
            rows = (
                flows.get("top_by_bytes")
                or flows.get("top")
                or flows.get("rows")
                or []
            )
            lines = []
            for r in rows:
                if isinstance(r, dict):
                    # flow_report отдаёт first_ts/last_ts; first_seen —
                    # fallback для отчётов старого формата.
                    ts = r.get("first_ts", r.get("first_seen", ""))
                    lines.append("\t".join(str(v) for v in (
                        ts, r.get("proto", ""),
                        r.get("src_ip", ""), r.get("src_port", ""),
                        r.get("dst_ip", ""), r.get("dst_port", ""),
                        r.get("bytes", ""),
                    )))
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            self._status_text.setText(tr("status.saved", path=path))
        except Exception as e:
            QMessageBox.critical(self, tr("error.save.title"), str(e))


    def _default_export_name(self, ext: str) -> str:
        report = self.run_view.last_report() or {}
        pcap = report.get("provenance", {}).get("pcap_path", "")
        stem = Path(pcap).stem if pcap else "report"
        return f"{stem}.{ext}"
