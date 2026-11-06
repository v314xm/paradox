"""Вкладка Экспорта (CSV, STIX, HTML) с копированием в буфер."""
import csv
import html
from pathlib import Path

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

from paradox.reporters.html_reporter import render_html
from paradox.reporters.stix_reporter import render_stix_json
from paradox_gui.i18n import tr


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
        self.format_combo.addItem(tr("export.fmt_html"), "html")
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
        return render_stix_json(self._report)

    def _generate_html(self) -> str:
        return render_html(self._report)

    def _generate(self, fmt: str) -> str:
        if fmt == "csv":
            return self._generate_csv()
        if fmt == "stix":
            return self._generate_stix()
        if fmt == "html":
            return self._generate_html()
        return ""

    def _update_preview(self):
        if not self._report: return

        fmt = self.format_combo.currentData()
        self._current_export_data = self._generate(fmt)

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

        specs = {
            "csv": (
                "Сохранить CSV", "findings.csv", "CSV (*.csv)",
                "export.csv_saved",
            ),
            "stix": (
                "Сохранить STIX", "bundle.json", "JSON (*.json)",
                "export.stix_saved",
            ),
            "html": (
                "Сохранить HTML", "report.html", "HTML (*.html)",
                "export.html_saved",
            ),
        }
        title, default_name, file_filter, ok_key = specs[fmt]
        path, _ = QFileDialog.getSaveFileName(
            self, title, default_name, file_filter,
        )
        if not path:
            return
        try:
            Path(path).write_text(self._current_export_data, encoding="utf-8")
            QMessageBox.information(self, "Success", tr(ok_key))
        except Exception as e:
            QMessageBox.critical(self, tr("export.err_save"), str(e))
