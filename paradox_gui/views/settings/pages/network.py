"""Страница настроек: network."""
from __future__ import annotations

import re

from PySide6.QtWidgets import (
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)
from paradox_gui.views.settings.parsers import (
    _format_lines,
    _format_ports,
)


class NetworkPageMixin:
    def _build_network_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.network.title"),
            tr("settings.network.subtitle"),
            "network",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._network_inputs: dict[str, object] = {}
        self._network_status: dict[str, QLabel] = {}

        self._add_smart_net_row(form, "suspicious_ports", tr("settings.network.suspicious_ports"), is_net=False)
        self._add_smart_net_row(form, "port_scan_excluded_ports", tr("settings.network.scan_excluded"), is_net=False)
        self._add_smart_net_row(form, "dc_service_ports", tr("settings.network.dc_ports"), is_net=False)
        self._add_smart_net_row(form, "lateral_movement_ports", tr("settings.network.lateral_ports"), is_net=False)
        self._add_smart_net_row(form, "beaconing_mail_polling_ports", tr("settings.network.mail_ports"), is_net=False)
        self._add_smart_net_row(form, "private_networks", tr("settings.network.private_nets"), is_net=True)

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_network, self._apply_network))

        self._load_network()
        return w


    def _add_smart_net_row(self, form, key, label, is_net=False):
        container = QWidget()
        vbox = QVBoxLayout(container)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(4)

        te = QPlainTextEdit()
        te.setObjectName("listField")
        te.setPlaceholderText(
            tr("settings.network.placeholder_nets") if is_net
            else tr("settings.network.placeholder_ports")
        )

        status_lbl = QLabel("")
        status_lbl.setObjectName("hint")
        status_lbl.setWordWrap(True)

        vbox.addWidget(te)
        vbox.addWidget(status_lbl)
        form.addRow(label, container)

        self._network_inputs[key] = te
        self._network_status[key] = status_lbl

        te.setProperty("is_net", is_net)
        te.textChanged.connect(lambda w=te, k=key: self._validate_and_preview_net(w, k))


    @staticmethod
    def _set_invalid(widget, invalid: bool) -> None:
        if widget.property("invalid") != invalid:
            widget.setProperty("invalid", invalid)
            widget.style().unpolish(widget)
            widget.style().polish(widget)


    @staticmethod
    def _set_net_status(label, text: str, error: bool = False) -> None:
        label.setProperty("level", "error" if error else "info")
        label.style().unpolish(label)
        label.style().polish(label)
        label.setText(text)


    def _validate_and_preview_net(self, widget: QPlainTextEdit, key: str) -> None:
        text = widget.toPlainText().strip()
        is_net = widget.property("is_net")
        status_lbl = self._network_status[key]

        if not text:
            self._set_invalid(widget, False)
            self._set_net_status(status_lbl, "")
            return

        tokens = [t for t in re.split(r'[\s,]+', text) if t]

        if is_net:
            valid, invalid = [], []
            for t in tokens:
                if re.match(r'^[0-9\./]+$', t):
                    valid.append(t)
                else:
                    invalid.append(t)

            if invalid:
                self._set_invalid(widget, True)
                self._set_net_status(
                    status_lbl,
                    tr("settings.network.invalid", tokens=", ".join(set(invalid))),
                    error=True,
                )
            else:
                self._set_invalid(widget, False)
                self._set_net_status(
                    status_lbl,
                    tr("settings.network.will_save", tokens=", ".join(valid)),
                )
        else:
            valid, invalid = [], []
            for t in tokens:
                if t.isdigit() and 1 <= int(t) <= 65535:
                    valid.append(str(int(t)))
                else:
                    invalid.append(t)

            if invalid:
                self._set_invalid(widget, True)
                self._set_net_status(
                    status_lbl,
                    tr(
                        "settings.network.invalid_ports",
                        tokens=", ".join(set(invalid)),
                    ),
                    error=True,
                )
            else:
                sorted_valid = sorted(list(set(int(p) for p in valid)))
                self._set_invalid(widget, False)
                self._set_net_status(
                    status_lbl,
                    tr(
                        "settings.network.will_save_n",
                        count=len(sorted_valid),
                        tokens=", ".join(map(str, sorted_valid)),
                    ),
                )


    def _load_network(self) -> None:
        try:
            from paradox.config import Config
            cfg = Config()
        except ImportError:
            return
        for key, widget in self._network_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(value, frozenset):
                if value and isinstance(next(iter(value)), int):
                    widget.setPlainText(_format_ports(value))
                else:
                    widget.setPlainText(_format_lines(value))
            elif isinstance(value, tuple):
                widget.setPlainText("\n".join(value))


    def _apply_network(self) -> None:
        values: dict = {}
        for key, widget in self._network_inputs.items():
            text = widget.toPlainText().strip()
            is_net = widget.property("is_net")
            tokens = [t for t in re.split(r'[\s,]+', text) if t]

            if is_net:
                valid = tuple(t for t in tokens if re.match(r'^[0-9\./]+$', t))
                values[key] = valid
            else:
                valid_ports = set()
                for t in tokens:
                    if t.isdigit() and 1 <= int(t) <= 65535:
                        valid_ports.add(int(t))
                values[key] = frozenset(valid_ports)

        self.config_applied.emit(values)
