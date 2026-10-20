"""Вкладка Экспорта (CSV и STIX) с копированием в буфер."""
import csv
import html
import ipaddress
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


def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def _extract_stix_iocs(findings: list) -> list[dict]:
    indicators = []
    seen_values = set()

    for f in findings:
        for ip_field in ("src_ip", "dst_ip"):
            ip = f.get(ip_field)
            if ip and not _is_private_ip(ip) and ip not in seen_values:
                seen_values.add(ip)
                indicators.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": datetime.now(UTC).isoformat(),
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now(UTC).isoformat(),
                    "name": "External IP",
                    "description": f"Найден в детекторе: {f.get('type')}"
                })

        val = str(f.get("value", ""))
        domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,})', val)
        if domain_match:
            domain = domain_match.group(1)
            if domain not in seen_values:
                seen_values.add(domain)
                indicators.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": datetime.now(UTC).isoformat(),
                    "pattern": f"[domain-name:value = '{domain}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now(UTC).isoformat(),
                    "name": "Domain",
                    "description": f"Найден в детекторе: {f.get('type')}"
                })

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

        lbl = QLabel("Экспорт данных (SIEM / Threat Intelligence)")
        lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        layout.addWidget(lbl)

        info = QLabel("Вы можете выгрузить Findings и IOC в формате CSV (для Excel) или STIX 2.1 (для SIEM/EDR).")
        info.setStyleSheet("color: #a0a0b0;")
        layout.addWidget(info)

        ctrl_layout = QHBoxLayout()

        self.format_combo = QComboBox()
        self.format_combo.addItem("CSV (Findings)", "csv")
        self.format_combo.addItem("STIX 2.1 (IOC Bundle)", "stix")
        self.format_combo.setMinimumWidth(250)
        self.format_combo.currentIndexChanged.connect(self._update_preview)
        ctrl_layout.addWidget(self.format_combo)

        self.btn_copy = QPushButton("Копировать в буфер")
        self.btn_copy.clicked.connect(self._on_copy_clicked)
        self.btn_copy.setEnabled(False)
        ctrl_layout.addWidget(self.btn_copy)

        self.btn_export = QPushButton("Сохранить в файл...")
        self.btn_export.setObjectName("primary")
        self.btn_export.clicked.connect(self._on_export_clicked)
        self.btn_export.setEnabled(False)
        ctrl_layout.addWidget(self.btn_export)

        ctrl_layout.addStretch()
        layout.addLayout(ctrl_layout)

        self.preview = QTextBrowser()
        self.preview.setStyleSheet("background: #2a2a35; border: 1px solid #444; border-radius: 4px; font-family: Consolas, monospace;")
        self.preview.setHtml("<p style='color:#888;'>Нет данных. Сначала выполните анализ pcap.</p>")
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
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": indicators
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
        QMessageBox.information(self, "Успех", "Полные данные скопированы в буфер обмена.\nМожно вставлять в SIEM или текстовый редактор.")

    def _on_export_clicked(self):
        if not self._report: return
        fmt = self.format_combo.currentData()

        if fmt == "csv":
            path, _ = QFileDialog.getSaveFileName(self, "Сохранить CSV", "findings.csv", "CSV (*.csv)")
            if not path: return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._current_export_data)
                QMessageBox.information(self, "Успех", "CSV успешно сохранен.")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Сохранить STIX", "bundle.json", "JSON (*.json)")
            if not path: return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._current_export_data)
                QMessageBox.information(self, "Успех", "STIX Bundle успешно сохранен.")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))
