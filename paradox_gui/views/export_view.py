"""Вкладка Экспорта (CSV и STIX) с копированием в буфер."""
import csv
import html
import json
import re
import uuid
from datetime import UTC, datetime

from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr


def _is_private_ip(ip_str: str) -> bool:
    from paradox.net_utils import is_private_ip
    return is_private_ip(ip_str)


# Fixed namespace for deterministic STIX indicator/bundle IDs.
_STIX_NS = uuid.UUID("b7e0c8d4-1a2f-4c5e-9f0a-3b4c5d6e7f80")


def _ts_to_iso(ts) -> str | None:
    """Unix timestamp -> ISO-8601 (UTC). None if missing/invalid."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=UTC).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def _stix_indicator_id(ioc_type: str, ioc: str) -> str:
    """Deterministic indicator UUIDv5 from (ioc_type, ioc)."""
    return f"indicator--{uuid.uuid5(_STIX_NS, f'{ioc_type}|{ioc}')}"


def _extract_stix_iocs(findings: list) -> list[dict]:
    """Extract IOCs from findings as STIX 2.1 indicators."""
    indicators: list[dict] = []
    seen_values: set[str] = set()

    def _emit(ioc_type: str, ioc: str, pattern: str, name: str,
              finding_type: str, first: str, last: str) -> None:
        if ioc in seen_values:
            return
        seen_values.add(ioc)
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_indicator_id(ioc_type, ioc),
            "created": first,
            "modified": first,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": first,
            "valid_until": last,
            "name": name,
            "description": f"Найден в детекторе: {finding_type}",
        })

    for f in findings:
        ftype = f.get("type", "?")
        first = _ts_to_iso(f.get("first_seen")) or datetime.now(UTC).isoformat()
        last = _ts_to_iso(f.get("last_seen")) or first

        for ip_field in ("src_ip", "dst_ip"):
            ip = f.get(ip_field)
            if ip and not _is_private_ip(ip):
                _emit(
                    "ipv4", ip,
                    f"[ipv4-addr:value = '{ip}']",
                    "External IP", ftype, first, last,
                )

        val = str(f.get("value", ""))
        domain_match = re.search(
            r'\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b', val,
        )
        if domain_match:
            domain = domain_match.group(1)
            _emit(
                "domain", domain,
                f"[domain-name:value = '{domain}']",
                "Domain", ftype, first, last,
            )

    return indicators

class ExportView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._report = None
        self._current_export_data = ""
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        lbl = QLabel(tr("export.title"))
        lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        layout.addWidget(lbl)

        info = QLabel(tr("export.subtitle"))
        info.setStyleSheet("color: #a0a0b0;")
        layout.addWidget(info)

        ctrl_layout = QHBoxLayout()

        self.format_combo = QComboBox()
        self.format_combo.addItem(tr("export.fmt_csv"), "csv")
        self.format_combo.addItem(tr("export.fmt_stix"), "stix")
        self.format_combo.setMinimumWidth(250)
        self.format_combo.currentIndexChanged.connect(self._update_preview)
        ctrl_layout.addWidget(self.format_combo)

        self.btn_copy = QPushButton(tr("export.copy"))
        self.btn_copy.clicked.connect(self._on_copy_clicked)
        self.btn_copy.setEnabled(False)
        ctrl_layout.addWidget(self.btn_copy)

        self.btn_export = QPushButton(tr("export.save"))
        self.btn_export.setObjectName("primary")
        self.btn_export.clicked.connect(self._on_export_clicked)
        self.btn_export.setEnabled(False)
        ctrl_layout.addWidget(self.btn_export)

        ctrl_layout.addStretch()
        layout.addLayout(ctrl_layout)

        self.preview = QTextBrowser()
        self.preview.setStyleSheet("background: #2a2a35; border: 1px solid #444; border-radius: 4px; font-family: Consolas, monospace;")
        self.preview.setHtml(f"<p style='color:#888;'>{tr('export.empty')}</p>")
        layout.addWidget(self.preview)

    def update_data(self, report: dict):
        self._report = report
        self.btn_export.setEnabled(True)
        self.btn_copy.setEnabled(True)
        self._update_preview()

    def _generate_csv(self) -> str:
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Value", "Severity", "Confidence", "MITRE", "Src IP", "Dst IP", "Description"])
        for f in self._report.get("findings", []):
            writer.writerow([
                f.get("type", ""), f.get("value", ""), f.get("severity", ""),
                f.get("confidence", ""), f.get("mitre_id", ""),
                f.get("src_ip", ""), f.get("dst_ip", ""), f.get("description", "")
            ])
        return output.getvalue()

    def _generate_stix(self) -> str:
        indicators = _extract_stix_iocs(self._report.get("findings", []))
        ids_key = "bundle|" + "|".join(
            sorted(ind["id"] for ind in indicators)
        )
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid5(_STIX_NS, ids_key)}",
            "objects": indicators,
        }
        return json.dumps(bundle, indent=4, ensure_ascii=False)

    def _update_preview(self):
        if not self._report: return

        fmt = self.format_combo.currentData()
        if fmt == "csv":
            self._current_export_data = self._generate_csv()
        else:
            self._current_export_data = self._generate_stix()

        # Экранируем HTML-символы для безопасного отображения
        display_text = html.escape(self._current_export_data)

        # Показываем полностью, без обрезки
        self.preview.setHtml(f"<pre style='color:#d4d4d4;'>{display_text}</pre>")

    def _on_copy_clicked(self):
        if not self._current_export_data:
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(self._current_export_data)
        QMessageBox.information(self, "Success", tr("export.copied"))

    def _on_export_clicked(self):
        if not self._report: return
        fmt = self.format_combo.currentData()

        if fmt == "csv":
            path, _ = QFileDialog.getSaveFileName(self, "Сохранить CSV", "findings.csv", "CSV (*.csv)")
            if not path: return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._current_export_data)
                QMessageBox.information(self, "Success", tr("export.csv_saved"))
            except Exception as e:
                QMessageBox.critical(self, tr("export.err_save"), str(e))
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Сохранить STIX", "bundle.json", "JSON (*.json)")
            if not path: return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._current_export_data)
                QMessageBox.information(self, "Success", tr("export.stix_saved"))
            except Exception as e:
                QMessageBox.critical(self, tr("export.err_save"), str(e))
