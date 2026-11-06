"""Секция «Противоречия» — заголовок + список карточек + скролл.

Собирает ContradictionCard'ы из report["contradictions"]. Если список
пуст — секция полностью скрывается.

Высота следит за содержимым: две-три карточки видны целиком, а на
четырёх включается внутренний скролл — иначе длинный список правил
уводит FindingsTable за край экрана.
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

    # Выше четырёх карточек список уходит во внутренний скролл.
    _MAX_LIST_HEIGHT = 380

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Preferred,
        )
        self._build_ui()
        self.setVisible(False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        header = QHBoxLayout()
        title = QLabel(tr("contra.section_title"))
        title.setObjectName("sectionTitle")
        self._count_label = QLabel("")
        self._count_label.setObjectName("panelCount")
        header.addWidget(title)
        header.addWidget(self._count_label)
        header.addStretch(1)
        layout.addLayout(header)

        self._list_container = QWidget()
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(6)
        # БЕЗ addStretch — он раздувает sizeHint контейнера.

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self._scroll.setWidget(self._list_container)
        layout.addWidget(self._scroll)

    def set_contradictions(self, contradictions: list[dict]) -> None:
        self._clear_cards()
        if not contradictions:
            self.setVisible(False)
            return
        self._count_label.setText(str(len(contradictions)))
        for contra in contradictions:
            card = ContradictionCard(contra)
            card.details_requested.connect(self.details_requested)
            self._list_layout.addWidget(card)
        self._fit_height()
        self.setVisible(True)

    def clear(self) -> None:
        self._clear_cards()
        self._count_label.setText("")
        self.setVisible(False)

    def _fit_height(self) -> None:
        """Высота по содержимому: карточки видны целиком, без обрезки."""
        self._list_container.adjustSize()
        content = min(
            self._list_layout.sizeHint().height(),
            self._MAX_LIST_HEIGHT,
        )
        chrome = (
            self.layout().contentsMargins().top()
            + self.layout().contentsMargins().bottom()
            + self.layout().itemAt(0).sizeHint().height()
            + self.layout().spacing()
        )
        self._scroll.setMinimumHeight(content)
        self.setMinimumHeight(content + chrome)
        self.setMaximumHeight(content + chrome)

    def _clear_cards(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
