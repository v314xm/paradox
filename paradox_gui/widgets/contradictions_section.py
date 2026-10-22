"""Секция «Противоречия» — заголовок + список карточек + скролл.

Собирает ContradictionCard'ы из report["contradictions"]. Если список
пуст — секция полностью скрывается.

ВАЖНО: секция НЕ растёт выше 260px. Иначе её внутренний QScrollArea
раздувает секцию и давит FindingsTable ниже.
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr
from paradox_gui.widgets.contradiction_card import ContradictionCard


class ContradictionsSection(QFrame):
    details_requested = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        # Жёсткий потолок — 260px. Это ключевое: даже если QScrollArea
        # внутри захочет больше, физически не сможет.
        self.setMaximumHeight(260)
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Maximum,
        )
        self._build_ui()
        self.setVisible(False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel(tr("contra.section_title"))
        title.setObjectName("h1")
        self._count_label = QLabel("")
        self._count_label.setObjectName("muted")
        header.addWidget(title)
        header.addWidget(self._count_label)
        header.addStretch(1)
        layout.addLayout(header)

        self._list_container = QWidget()
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(8)
        # БЕЗ addStretch — он раздувает sizeHint контейнера.

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(self._list_container)
        layout.addWidget(scroll)

    def set_contradictions(self, contradictions: list[dict]) -> None:
        self._clear_cards()
        if not contradictions:
            self.setVisible(False)
            return
        self._count_label.setText(f"({len(contradictions)})")
        for contra in contradictions:
            card = ContradictionCard(contra)
            card.details_requested.connect(self.details_requested)
            self._list_layout.addWidget(card)
        self.setVisible(True)

    def clear(self) -> None:
        self._clear_cards()
        self._count_label.setText("")
        self.setVisible(False)

    def _clear_cards(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
