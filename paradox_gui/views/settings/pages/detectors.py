"""Страница настроек: detectors."""
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

from paradox_gui.detector_help import get_detector_help
from paradox_gui.i18n import (
    tr,
)
from paradox_gui.views.settings.constants import (
    _DETECTORS,
)


class DetectorsPageMixin:
    def _build_detectors_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.detectors.title"),
            tr("settings.detectors.subtitle"),
            "detectors",
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

        self._detector_boxes: dict[str, object] = {}
        for name, label in _DETECTORS:
            box_layout.addWidget(self._make_detector_row(name, label))
        box_layout.addStretch(1)

        scroll.setWidget(box_host)
        outer.addWidget(scroll, stretch=1)

        buttons = QHBoxLayout()
        all_btn = QPushButton(tr("settings.btn.enable_all"))
        all_btn.clicked.connect(lambda: self._set_all_detectors(True))
        none_btn = QPushButton(tr("settings.btn.disable_all"))
        none_btn.clicked.connect(lambda: self._set_all_detectors(False))
        buttons.addWidget(all_btn)
        buttons.addWidget(none_btn)
        buttons.addStretch(1)
        apply_btn = QPushButton(tr("settings.btn.apply"))
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self._apply_detectors)
        buttons.addWidget(apply_btn)
        outer.addLayout(buttons)

        return w


    def _make_detector_row(self, name: str, label: str) -> QWidget:
        """Строка детектора: [чекбокс с названием] [описание справа]."""
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 2, 0, 2)
        h.setSpacing(12)

        cb = QCheckBox(label)
        cb.setChecked(True)
        cb.setMinimumWidth(220)
        h.addWidget(cb)

        help_text = get_detector_help(name)
        hint = QLabel(help_text)
        hint.setWordWrap(True)
        hint.setObjectName("hint")
        hint.setToolTip(help_text)
        h.addWidget(hint, stretch=1)

        self._detector_boxes[name] = cb
        return row


    def _set_all_detectors(self, checked: bool) -> None:
        for cb in self._detector_boxes.values():
            cb.setChecked(checked)


    def _apply_detectors(self) -> None:
        disabled = {
            name for name, cb in self._detector_boxes.items()
            if not cb.isChecked()
        }
        self.detectors_applied.emit(disabled)
