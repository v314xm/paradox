"""Страница настроек: allowlist."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QVBoxLayout,
    QWidget,
)

from paradox_gui.field_help import (
    get_field_help,
)
from paradox_gui.i18n import (
    tr,
)
from paradox_gui.views.settings.parsers import (
    _format_lines,
    _parse_lines,
)
from paradox_gui.widgets.editable_list import (
    PORT_FIELDS,
    EditableListWidget,
)


class AllowlistPageMixin:
    def _build_allowlist_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.allowlist.title"),
            tr("settings.allowlist.subtitle"),
            "allowlist",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._allowlist_inputs: dict[str, object] = {}

        self._add_list_row_al(form, "beaconing_allowlist_suffixes",
                              tr("settings.allowlist.beaconing_suffixes"),
                              height=200)
        self._add_list_row_al(form, "beaconing_allowlist_ips",
                              tr("settings.allowlist.beaconing_ips"),
                              height=80)
        self._add_list_row_al(form, "dns_tunneling_allowlist",
                              tr("settings.allowlist.dns_tunneling"),
                              height=80)
        self._add_list_row_al(form, "sni_mismatch_allowlist",
                              tr("settings.allowlist.sni_mismatch"),
                              height=140)
        self._add_list_row_al(form, "large_transfer_excluded_hosts",
                              tr("settings.allowlist.large_transfer_hosts"),
                              height=120)
        self._add_list_row_al(form, "large_transfer_excluded_user_agents",
                              tr("settings.allowlist.large_transfer_uas"),
                              height=80)

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_allowlist, self._apply_allowlist))

        self._load_allowlist()
        return w


    def _add_list_row_al(self, form, key, label, height=90):
        w = EditableListWidget(
            port_mode=(key in PORT_FIELDS),
            help_text=get_field_help(key),
        )
        form.addRow(label, w)
        self._allowlist_inputs[key] = w


    def _load_allowlist(self) -> None:
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._allowlist_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(value, (frozenset, tuple, set, list)):
                widget.setPlainText(_format_lines(value))


    def _apply_allowlist(self) -> None:
        values: dict = {}
        for key, widget in self._allowlist_inputs.items():
            values[key] = _parse_lines(widget.toPlainText())
        self.config_applied.emit(values)
