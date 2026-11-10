"""Общие строители форм и строк настроек."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.field_help import (
    SECTION_BY_TITLE,
    get_field_help,
    get_section_help,
)
from paradox_gui.i18n import (
    tr,
)
from paradox_gui.views.settings.constants import (
    _SECTIONS,
)


class BuildersMixin:
    def _make_scroll_form(self):
        """QScrollArea + QFormLayout внутри. Возвращает (scroll, form, host).

        Все секции однотипны: заголовок, подпись, прокручиваемая форма,
        кнопки снизу. Хелпер убирает дублирование.
        """
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        host = QWidget()
        form = QFormLayout(host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(14)
        # Label слева, верхнее выравнивание — чтобы название поля было
        # на одном уровне со спиннером, а описание уходило под ним.
        form.setLabelAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        form.setFormAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        # FieldsStayAtSizeHint — спиннеры фикс. ширины. Label-колонке
        # это не мешает растягиваться: у label-виджета Expanding, а
        # форма при нехватке места отдаёт свободное место ему.
        form.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint
        )
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.DontWrapRows)
        scroll.setWidget(host)
        return scroll, form


    def _make_header(self, title: str, subtitle: str, section_key: str | None = None) -> tuple[QLabel, QLabel]:
        t = QLabel(title)
        t.setObjectName("h1")
        s = QLabel(subtitle)
        s.setObjectName("muted")
        s.setWordWrap(True)
        if section_key is None:
            section_key = SECTION_BY_TITLE.get(title)
        if section_key is None:
            # Заголовки секций переводятся, поэтому карта по русским
            # подписям в EN не срабатывает — сверяемся с tr().
            for key, _label in _SECTIONS:
                if title == tr(f"settings.{key}.title"):
                    section_key = key
                    break
        if section_key:
            help_text = get_section_help(section_key)
            if help_text:
                t.setToolTip(help_text)
                s.setToolTip(help_text)
        return t, s


    def _make_buttons(self, reset_slot, apply_slot) -> QHBoxLayout:
        h = QHBoxLayout()
        h.addStretch(1)
        rst = QPushButton(tr("settings.btn.reset"))
        rst.clicked.connect(reset_slot)
        apt = QPushButton(tr("settings.btn.apply"))
        apt.setObjectName("primary")
        apt.clicked.connect(apply_slot)
        h.addWidget(rst)
        h.addWidget(apt)
        return h


    def _label_with_hint(self, label_text: str, key: str):
        """QWidget: [label сверху] [hint под ним серым].

        Хост растягивается по горизонтали (Expanding), чтобы QFormLayout
        отдал описанию всю доступную ширину. Спиннер справа остаётся
        фиксированной ширины (160px) — он не участвует в stretch.
        """
        from PySide6.QtWidgets import QSizePolicy


        host = QWidget()
        host.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred,
        )
        # QFormLayout при FieldsStayAtSizeHint отдаёт label-колонке
        # ровно sizeHint. Без явного минимума Expanding игнорируется.
        host.setMinimumWidth(620)
        v = QVBoxLayout(host)
        v.setContentsMargins(0, 0, 12, 6)
        v.setSpacing(2)

        lbl = QLabel(label_text)
        v.addWidget(lbl)

        text = get_field_help(key)
        hint = QLabel(text)
        hint.setWordWrap(True)
        hint.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred,
        )
        hint.setObjectName("hint")
        hint.setToolTip(text)
        v.addWidget(hint)

        if not hasattr(self, "_field_hints"):
            self._field_hints: dict[str, QLabel] = {}
        self._field_hints[key] = hint
        return host


    def _add_int_row(self, form, key: str, label: str,
                     lo: int = 0, hi: int = 1_000_000_000) -> None:
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._threshold_inputs[key] = sp


    def _add_float_row(self, form, key: str, label: str,
                       step: float = 0.1, lo: float = 0.0,
                       hi: float = 1000.0) -> None:
        sp = QDoubleSpinBox()
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setDecimals(3)
        sp.setFixedWidth(160)
        form.addRow(self._label_with_hint(label, key), sp)
        self._threshold_inputs[key] = sp
