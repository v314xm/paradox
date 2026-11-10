"""Страница настроек: plugins."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import (
    tr,
)


class PluginsPageMixin:
    def _build_plugins_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.plugins.title"),
            tr("settings.plugins.subtitle"),
            "plugins",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        form = QFormLayout()
        form.setSpacing(14)
        self._plugins_inputs: dict[str, object] = {}

        self._plugins_enabled = QCheckBox(tr("settings.plugins.enabled"))
        self._plugins_inputs["plugins_enabled"] = self._plugins_enabled
        form.addRow("", self._plugins_enabled)

        dir_row = QHBoxLayout()
        self._plugins_dir = QLineEdit()
        self._plugins_dir.setFixedWidth(380)
        self._plugins_dir.setPlaceholderText("~/.paradox/plugins")
        self._plugins_inputs["plugins_dir"] = self._plugins_dir
        dir_row.addWidget(self._plugins_dir)

        browse = QPushButton("…")
        browse.setFixedWidth(32)
        browse.clicked.connect(self._choose_plugins_dir)
        dir_row.addWidget(browse)
        dir_row.addStretch()
        form.addRow(tr("settings.plugins.dir"), dir_row)

        outer.addLayout(form)

        self._plugins_status = QLabel("")
        self._plugins_status.setWordWrap(True)
        self._plugins_status.setObjectName("muted")
        outer.addWidget(self._plugins_status)

        check = QPushButton(tr("settings.plugins.check"))
        check.clicked.connect(self._check_plugins)
        outer.addWidget(check, alignment=Qt.AlignmentFlag.AlignLeft)
        outer.addStretch(1)

        outer.addLayout(
            self._make_buttons(self._load_plugins, self._apply_plugins),
        )

        self._load_plugins()
        return w


    def _load_plugins(self) -> None:
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        self._plugins_enabled.setChecked(
            bool(getattr(cfg, "plugins_enabled", False)),
        )
        self._plugins_dir.setText(str(getattr(cfg, "plugins_dir", "")))
        self._check_plugins()


    def _apply_plugins(self) -> None:
        directory = self._plugins_dir.text().strip()
        if not directory:
            QMessageBox.warning(
                self,
                tr("settings.plugins.title"),
                tr("settings.plugins.empty_dir"),
            )
            return
        self.config_applied.emit({
            "plugins_enabled": self._plugins_enabled.isChecked(),
            "plugins_dir": Path(directory).expanduser(),
        })
        self._check_plugins()


    def _choose_plugins_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self,
            tr("settings.plugins.dir"),
            self._plugins_dir.text().strip(),
        )
        if chosen:
            self._plugins_dir.setText(chosen)


    def _check_plugins(self) -> None:
        """Показать, какие плагины загрузятся с текущими настройками."""
        try:
            from paradox.config import Config
            from paradox.detector_plugins import load_detector_plugins
        except ImportError:
            return

        status = getattr(self, "_plugins_status", None)
        if status is None:
            return

        if not self._plugins_enabled.isChecked():
            status.setText(tr("settings.plugins.off"))
            status.setToolTip("")
            return

        directory = Path(
            self._plugins_dir.text().strip() or ".",
        ).expanduser()
        if not directory.is_dir():
            status.setText(f"{tr('settings.plugins.missing')}: {directory}")
            status.setToolTip("")
            return

        config = Config(
            plugins_enabled=True,
            plugins_dir=directory,
        )
        result = load_detector_plugins(config)
        if not result.detectors:
            text = f"{tr('settings.plugins.none')}: {directory}"
        else:
            names = ", ".join(det.name for det in result.detectors)
            text = (
                f"{tr('settings.plugins.loaded')}: "
                f"{len(result.detectors)} — {names}"
            )
        if result.errors:
            text += f" · {tr('settings.plugins.errors')}: {len(result.errors)}"
        status.setText(text)
        status.setToolTip("\n".join(result.errors))
