"""Страница настроек: dga."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)
from paradox_gui.views.settings.parsers import (
    _format_lines,
    _parse_lines,
)
from paradox_gui.widgets.editable_list import (
    EditableListWidget,
)


class DgaPageMixin:
    def _build_dga_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.dga.title"),
            tr("settings.dga.subtitle"),
            "dga",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._dga_inputs: dict[str, object] = {}

        self._dga_allowlist = EditableListWidget(port_mode=False)
        form.addRow(tr("settings.dga.allowlist_label"), self._dga_allowlist)
        self._dga_inputs["dga_allowlist"] = self._dga_allowlist

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_dga, self._apply_dga))

        self._load_dga()
        return w


    def _load_dga(self) -> None:
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        value = getattr(cfg, "dga_allowlist", None)
        if value:
            self._dga_allowlist.setPlainText(_format_lines(value))


    def _apply_dga(self) -> None:
        values = {
            "dga_allowlist": _parse_lines(self._dga_allowlist.toPlainText()),
        }
        self.config_applied.emit(values)
