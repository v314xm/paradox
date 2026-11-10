"""Страница настроек: general."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    language_display_name,
    tr,
)


class GeneralPageMixin:
    def _build_general_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.general.title"),
            tr("settings.general.subtitle"),
        )
        outer.addWidget(t)
        outer.addWidget(s)

        form = QFormLayout()
        form.setSpacing(14)

        self._lang_combo = QComboBox()
        for _code in SUPPORTED_LANGUAGES:
            self._lang_combo.addItem(language_display_name(_code), _code)

        # Загружаем текущий язык
        if self._store:
            current_lang = self._store.load().get("language", DEFAULT_LANGUAGE)
            idx = self._lang_combo.findData(current_lang)
            if idx >= 0:
                self._lang_combo.setCurrentIndex(idx)

        self._lang_combo.currentIndexChanged.connect(self._on_lang_changed)
        form.addRow(tr("settings.general.language"), self._lang_combo)
        outer.addLayout(form)
        outer.addStretch(1)
        return w


    def _on_lang_changed(self, index: int) -> None:
        lang = self._lang_combo.itemData(index)
        if self._store and lang:
            self._store.save_partial(language=lang)
            QMessageBox.information(
                self,
                tr("dialog.lang_changed.title"),
                tr("dialog.lang_changed.body"),
            )
