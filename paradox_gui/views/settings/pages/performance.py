"""Страница настроек: performance."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)


class PerformancePageMixin:
    def _build_performance_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.perf.title"),
            tr("settings.perf.subtitle"),
            "perf",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        host = QWidget()
        form = QFormLayout(host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(16)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        scroll.setWidget(host)

        self._perf_inputs: dict[str, object] = {}

        # --- TCP Reassembly ---
        cb_reassembly = QCheckBox(tr("settings.perf.reassembly"))
        lbl_reassembly = QLabel(tr("settings.perf.reassembly_hint"))
        lbl_reassembly.setObjectName("hint")
        lbl_reassembly.setWordWrap(True)
        form.addRow(cb_reassembly, lbl_reassembly)
        self._perf_inputs["tcp_reassembly_enabled"] = cb_reassembly
        if not hasattr(self, "_field_hints"):
            self._field_hints = {}
        self._field_hints["tcp_reassembly_enabled"] = lbl_reassembly

        # --- File Carve ---
        cb_carve = QCheckBox(tr("settings.perf.carve"))
        lbl_carve = QLabel(tr("settings.perf.carve_hint"))
        lbl_carve.setObjectName("hint")
        lbl_carve.setWordWrap(True)
        form.addRow(cb_carve, lbl_carve)
        self._perf_inputs["file_carve_enabled"] = cb_carve
        if not hasattr(self, "_field_hints"):
            self._field_hints = {}
        self._field_hints["file_carve_enabled"] = lbl_carve

        cb_write = QCheckBox(tr("settings.perf.write_body"))
        lbl_write = QLabel(tr("settings.perf.write_body_hint"))
        lbl_write.setObjectName("hintDanger")
        lbl_write.setWordWrap(True)
        form.addRow(cb_write, lbl_write)
        self._perf_inputs["file_carve_write_body"] = cb_write
        if not hasattr(self, "_field_hints"):
            self._field_hints = {}
        self._field_hints["file_carve_write_body"] = lbl_write

        # --- HTTP/2 и TLS ---
        cb_http2 = QCheckBox(tr("settings.perf.http2"))
        lbl_http2 = QLabel(tr("settings.perf.http2_hint"))
        lbl_http2.setObjectName("hint")
        lbl_http2.setWordWrap(True)
        form.addRow(cb_http2, lbl_http2)
        self._perf_inputs["http2_enabled"] = cb_http2
        self._field_hints["http2_enabled"] = lbl_http2

        keylog = QLineEdit()
        keylog.setPlaceholderText(tr("settings.perf.keylog_placeholder"))
        btn_keylog = QPushButton(tr("settings.perf.browse"))
        btn_keylog.clicked.connect(
            lambda: self._browse_keylog_file(keylog),
        )
        keylog_row = QHBoxLayout()
        keylog_row.addWidget(keylog, stretch=1)
        keylog_row.addWidget(btn_keylog)

        lbl_keylog = QLabel(tr("settings.perf.keylog_hint"))
        lbl_keylog.setObjectName("hint")
        lbl_keylog.setWordWrap(True)
        form.addRow(tr("settings.perf.keylog"), keylog_row)
        form.addRow("", lbl_keylog)
        self._perf_inputs["tls_keylog_path"] = keylog
        self._field_hints["tls_keylog_path"] = lbl_keylog

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_performance, self._apply_performance))

        self._load_performance()
        return w


    def _browse_keylog_file(self, field: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("settings.perf.keylog_dialog"),
            "",
            tr("settings.perf.keylog_filter"),
        )
        if path:
            field.setText(path)


    def _load_performance(self) -> None:
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._perf_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                if isinstance(widget, QLineEdit):
                    widget.setText("")
                continue
            if isinstance(widget, QCheckBox):
                widget.setChecked(bool(value))
            elif isinstance(widget, QSpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, QLineEdit):
                widget.setText(str(value))


    def _apply_performance(self) -> None:
        values: dict = {}
        for key, widget in self._perf_inputs.items():
            if isinstance(widget, QCheckBox):
                values[key] = widget.isChecked()
            elif isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QLineEdit):
                values[key] = widget.text().strip() or None
        self.config_applied.emit(values)
