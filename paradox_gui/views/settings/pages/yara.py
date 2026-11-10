"""Страница настроек: yara."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)


class YaraPageMixin:
    def _validate_yara_rules(self) -> None:
        try:
            import yara
        except ImportError:
            QMessageBox.warning(
                self, "YARA", tr("settings.yara.err_module")
            )
            return

        path = self._yara_path.text().strip()
        if not path:
            QMessageBox.warning(
                self, "YARA", tr("settings.yara.err_no_path")
            )
            return

        try:
            rules = yara.compile(filepath=path)
            QMessageBox.information(
                self,
                "YARA",
                tr(
                    "settings.yara.ok_loaded",
                    count=sum(1 for _ in rules),
                ),
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                tr("settings.yara.err_rules_title"),
                tr(
                    "settings.yara.err_rules",
                    type=type(e).__name__,
                    err=e,
                ),
            )


    def _build_yara_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.yara.title"),
            tr("settings.yara.subtitle"),
            "yara",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll, form = self._make_scroll_form()
        self._yara_inputs = {}

        self._yara_path = QLineEdit()
        self._yara_path.setPlaceholderText(
            tr("settings.yara.path_placeholder")
        )
        self._yara_path.setFixedWidth(420)

        btn_browse = QPushButton(tr("settings.yara.browse"))
        btn_browse.clicked.connect(self._browse_yara_file)

        btn_validate = QPushButton(tr("settings.yara.validate"))
        btn_validate.clicked.connect(self._validate_yara_rules)

        row = QHBoxLayout()
        row.addWidget(self._yara_path)
        row.addWidget(btn_browse)
        row.addWidget(btn_validate)
        row.addStretch(1)

        form.addRow(tr("settings.yara.path"), row)
        self._yara_inputs["yara_rules_path"] = self._yara_path

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(self._load_yara, self._apply_yara))

        self._load_yara()
        return w


    def _browse_yara_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr("settings.yara.dialog_title"),
            "",
            tr("settings.yara.filter"),
        )
        if path:
            self._yara_path.setText(path)


    def _load_yara(self) -> None:
        try:
            from paradox.config import Config
            cfg = Config()
            val = getattr(cfg, "yara_rules_path", None)
            if val:
                self._yara_path.setText(str(val))
            else:
                self._yara_path.clear()
        except ImportError:
            pass


    def _apply_yara(self) -> None:
        text = self._yara_path.text().strip()
        values = {"yara_rules_path": text if text else None}
        self.config_applied.emit(values)
