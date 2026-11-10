"""Страница настроек: thresholds."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)


class ThresholdsPageMixin:
    def _build_thresholds_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.thresholds.title"),
            tr("settings.thresholds.subtitle"),
            "thresholds",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        outer.addLayout(self._build_profile_row())

        scroll, form = self._make_scroll_form()
        self._threshold_inputs: dict[str, object] = {}

        self._add_int_row(form, "dga_min_label_length", tr("settings.field.dga_min_label_length"))
        self._add_float_row(form, "dga_entropy_threshold", tr("settings.field.dga_entropy_threshold"), step=0.1)
        self._add_int_row(form, "nxdomain_burst_threshold", tr("settings.field.nxdomain_burst_threshold"))
        self._add_int_row(form, "nxdomain_burst_window_sec",
                          tr("settings.field.nxdomain_burst_window_sec"), lo=1, hi=86400)
        self._add_float_row(form, "nxdomain_burst_min_ratio",
                            tr("settings.field.nxdomain_burst_min_ratio"),
                            step=0.05, lo=0.0, hi=1.0)
        self._add_int_row(form, "dns_tunneling_min_qname_length", tr("settings.field.dns_tunneling_min_qname_length"))
        self._add_int_row(form, "dns_tunneling_min_queries", tr("settings.field.dns_tunneling_min_queries"))
        self._add_int_row(form, "brute_force_min_flows", tr("settings.field.brute_force_min_flows"))
        self._add_int_row(form, "brute_force_max_avg_packets", tr("settings.field.brute_force_max_avg_packets"))
        self._add_int_row(form, "ftp_brute_force_min_flows", tr("settings.field.ftp_brute_force_min_flows"))
        self._add_int_row(form, "beaconing_min_connections", tr("settings.field.beaconing_min_connections"))
        self._add_int_row(form, "beaconing_min_duration_sec", tr("settings.field.beaconing_min_duration_sec"))
        self._add_float_row(form, "beaconing_max_jitter_ratio", tr("settings.field.beaconing_max_jitter_ratio"), step=0.01)
        self._add_int_row(form, "large_transfer_min_bytes", tr("settings.field.large_transfer_min_bytes"))
        self._add_int_row(form, "port_scan_min_distinct_dsts", tr("settings.field.port_scan_min_distinct_dsts"))
        self._add_int_row(form, "port_scan_max_flows_per_dst", tr("settings.field.port_scan_max_flows_per_dst"))
        self._add_float_row(form, "reverse_asymmetry_min_ratio", tr("settings.field.reverse_asymmetry_min_ratio"), step=0.5)
        self._add_int_row(form, "reverse_asymmetry_min_total_bytes", tr("settings.field.reverse_asymmetry_min_total_bytes"))

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_thresholds, self._apply_thresholds))

        self._load_thresholds()
        return w


    def _load_thresholds(self) -> None:
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._threshold_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(widget, QSpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, QDoubleSpinBox):
                widget.setValue(float(value))


    def _apply_thresholds(self) -> None:
        values = {}
        for key, widget in self._threshold_inputs.items():
            if isinstance(widget, QSpinBox) or isinstance(widget, QDoubleSpinBox):
                values[key] = widget.value()
        self.thresholds_applied.emit(values)
