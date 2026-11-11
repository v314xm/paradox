"""Страница настроек: reports."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)


class ReportsPageMixin:
    def _build_reports_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.reports.title"),
            tr("settings.reports.subtitle"),
            "reports",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._reports_inputs: dict[str, object] = {}

        self._output_dir = QLineEdit()
        self._output_dir.setPlaceholderText("reports")
        self._output_dir.setFixedWidth(420)
        form.addRow(tr("settings.reports.output_dir"), self._output_dir)
        self._reports_inputs["output_dir"] = self._output_dir

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_reports, self._apply_reports))

        self._load_reports()
        return w


    def _load_reports(self) -> None:
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        value = getattr(cfg, "output_dir", None)
        if value is not None:
            self._output_dir.setText(str(value))


    def _apply_reports(self) -> None:
        text = self._output_dir.text().strip() or "reports"
        path = Path(text)
        # Создаём сразу: Config файловую систему не трогает —
        # каталог отчётов появляется только здесь.
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Не критично: если путь невалидный, ядро само отвалится
            # позже с понятной ошибкой. Молча пропускаем.
            pass
        self.config_applied.emit({"output_dir": path})
