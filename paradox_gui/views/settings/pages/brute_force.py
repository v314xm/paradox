"""Страница настроек: brute."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QPlainTextEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)
from paradox_gui.views.settings.parsers import (
    _format_lines,
    _format_ports,
    _parse_lines,
    _parse_ports_with_report,
)
from paradox_gui.widgets.editable_list import (
    EditableListWidget,
)


class BruteForcePageMixin:
    def _build_brute_force_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.brute.title"),
            tr("settings.brute.subtitle"),
            "brute",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._brute_inputs: dict[str, object] = {}

        self._add_int_row_bf(form, "brute_force_min_unique_src_ports",
                             tr("settings.field.brute_force_min_unique_src_ports"), lo=1, hi=10000)
        self._add_float_row_bf(form, "brute_force_uri_ratio_threshold",
                               tr("settings.field.brute_force_uri_ratio_threshold"),
                               lo=0.01, hi=1.0, step=0.05, decimals=2)
        self._add_float_row_bf(form, "brute_force_min_rate_flows_per_sec",
                               tr("settings.field.brute_force_min_rate_flows_per_sec"),
                               lo=0.001, hi=1000.0, step=0.01, decimals=3)
        self._add_int_row_bf(form, "ftp_brute_force_min_unique_src_ports",
                             tr("settings.field.ftp_brute_force_min_unique_src_ports"), lo=1, hi=10000)

        self._bf_skip_tls = EditableListWidget(port_mode=True)
        form.addRow(tr("settings.brute.skip_tls_label"), self._bf_skip_tls)
        self._brute_inputs["brute_force_skip_tls_ports"] = self._bf_skip_tls

        self._bf_login_hints = EditableListWidget(port_mode=False)
        form.addRow(tr("settings.brute.login_hints_label"), self._bf_login_hints)
        self._brute_inputs["login_endpoint_hints"] = self._bf_login_hints

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_brute_force, self._apply_brute_force))

        self._load_brute_force()
        return w


    def _add_int_row_bf(self, form, key, label, lo, hi):
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._brute_inputs[key] = sp


    def _add_float_row_bf(self, form, key, label, lo, hi, step, decimals):
        sp = QDoubleSpinBox()
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setDecimals(decimals)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._brute_inputs[key] = sp


    def _load_brute_force(self) -> None:
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._brute_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(widget, QSpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, QDoubleSpinBox):
                widget.setValue(float(value))
            elif isinstance(widget, (QPlainTextEdit, EditableListWidget)):
                if isinstance(value, frozenset):
                    if value and isinstance(next(iter(value)), int):
                        widget.setPlainText(_format_ports(value))
                    else:
                        widget.setPlainText(_format_lines(value))


    def _apply_brute_force(self) -> None:
        values: dict = {}
        skipped_total = 0
        previews: list[str] = []
        for key, widget in self._brute_inputs.items():
            if isinstance(widget, QSpinBox) or isinstance(widget, QDoubleSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QPlainTextEdit):
                text = widget.toPlainText()
                if "ports" in key or "skip_tls" in key:
                    parsed, skipped = _parse_ports_with_report(text)
                    values[key] = parsed
                    skipped_total += len(skipped)
                    if skipped:
                        previews.append(f"{key}: {', '.join(skipped[:3])}")
                else:
                    values[key] = _parse_lines(text)
        if skipped_total:
            self._notify_status(
                tr(
                    "settings.status.invalid_tokens",
                    count=skipped_total,
                    tokens="; ".join(previews[:2]),
                ),
                level="warn",
            )
        self.config_applied.emit(values)
