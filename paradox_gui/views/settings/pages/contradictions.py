"""Страница настроек: contradictions."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.contradiction_help import get_contradiction_help
from paradox_gui.i18n import (
    tr,
)
from paradox_gui.views.settings.constants import (
    _CONTRADICTIONS,
)


class ContradictionsPageMixin:
    def _build_contradictions_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.contradictions.title"),
            tr("settings.contradictions.subtitle"),
            "contradictions",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        box_host = QWidget()
        box_layout = QVBoxLayout(box_host)
        box_layout.setContentsMargins(0, 8, 0, 8)
        box_layout.setSpacing(4)

        self._contradiction_boxes: dict[str, object] = {}
        for name, label in _CONTRADICTIONS:
            box_layout.addWidget(self._make_contradiction_row(name, label))
        box_layout.addStretch(1)

        scroll.setWidget(box_host)
        outer.addWidget(scroll, stretch=1)

        buttons = QHBoxLayout()
        all_btn = QPushButton(tr("settings.btn.enable_all"))
        all_btn.clicked.connect(lambda: self._set_all_contradictions(True))
        none_btn = QPushButton(tr("settings.btn.disable_all"))
        none_btn.clicked.connect(lambda: self._set_all_contradictions(False))
        buttons.addWidget(all_btn)
        buttons.addWidget(none_btn)
        buttons.addStretch(1)
        apply_btn = QPushButton(tr("settings.btn.apply"))
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_contradictions)
        buttons.addWidget(apply_btn)
        outer.addLayout(buttons)

        return w


    def _make_contradiction_row(self, name: str, label: str) -> QWidget:
        """Строка правила: [чекбокс] [описание справа]."""
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 2, 0, 2)
        h.setSpacing(12)

        cb = QCheckBox(label)
        cb.setChecked(True)
        cb.setMinimumWidth(320)
        h.addWidget(cb)

        help_text = get_contradiction_help(name)
        hint = QLabel(help_text)
        hint.setWordWrap(True)
        hint.setObjectName("hint")
        hint.setToolTip(help_text)
        h.addWidget(hint, stretch=1)

        self._contradiction_boxes[name] = cb
        return row


    def _set_all_contradictions(self, checked: bool) -> None:
        for cb in self._contradiction_boxes.values():
            cb.setChecked(checked)


    def _apply_contradictions(self) -> None:
        disabled = {
            name for name, cb in self._contradiction_boxes.items()
            if not cb.isChecked()
        }
        self.contradictions_applied.emit(disabled)
