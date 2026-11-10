"""Страница настроек: threatintel."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QScrollArea,
    QSpinBox,
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


class ThreatIntelPageMixin:
    def _build_threatintel_page(self) -> QWidget:
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(12)

        t, s = self._make_header(
            tr("settings.threatintel.title"),
            tr("settings.threatintel.subtitle"),
            "threatintel",
        )
        outer.addWidget(t)
        outer.addWidget(s)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        host = QWidget()
        host.setMaximumWidth(760)
        form = QFormLayout(host)
        form.setContentsMargins(0, 8, 0, 8)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        scroll.setWidget(host)

        self._ti_inputs: dict[str, object] = {}

        # --- Провайдеры ---
        te_prov = QPlainTextEdit()
        te_prov.setFixedHeight(80)
        te_prov.setMaximumWidth(500)
        form.addRow(tr("settings.threatintel.providers"), te_prov)
        self._ti_inputs["enrichment_enabled_providers"] = te_prov

        # --- API-ключи ---
        self._ti_abuse_key = QLineEdit()
        self._ti_abuse_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_abuse_key.setPlaceholderText("ABUSEIPDB_API_KEY")
        self._ti_abuse_key.setMaximumWidth(420)
        form.addRow(tr("settings.threatintel.abuseipdb_key"), self._ti_abuse_key)

        self._ti_vt_key = QLineEdit()
        self._ti_vt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_vt_key.setPlaceholderText("VIRUSTOTAL_API_KEY")
        self._ti_vt_key.setMaximumWidth(420)
        form.addRow(tr("settings.threatintel.vt_key"), self._ti_vt_key)

        self._ti_abusech_key = QLineEdit()
        self._ti_abusech_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_abusech_key.setPlaceholderText("ABUSECH_AUTH_KEY (MalwareBazaar, ThreatFox, URLhaus)")
        self._ti_abusech_key.setMaximumWidth(420)
        form.addRow(tr("settings.threatintel.abusech_key"), self._ti_abusech_key)

        self._ti_otx_key = QLineEdit()
        self._ti_otx_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_otx_key.setPlaceholderText("OTX_API_KEY")
        self._ti_otx_key.setMaximumWidth(420)
        form.addRow(tr("settings.threatintel.otx_key"), self._ti_otx_key)

        self._ti_greynoise_key = QLineEdit()
        self._ti_greynoise_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_greynoise_key.setPlaceholderText("GREYNOISE_API_KEY")
        self._ti_greynoise_key.setMaximumWidth(420)
        form.addRow(tr("settings.threatintel.greynoise_key"), self._ti_greynoise_key)

        self._ti_urlscan_key = QLineEdit()
        self._ti_urlscan_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._ti_urlscan_key.setPlaceholderText("URLSCAN_API_KEY")
        self._ti_urlscan_key.setMaximumWidth(420)
        form.addRow(tr("settings.threatintel.urlscan_key"), self._ti_urlscan_key)

        show_cb = QCheckBox(tr("settings.threatintel.show_keys"))
        show_cb.toggled.connect(self._toggle_api_keys_visibility)
        form.addRow("", show_cb)

        shodan_note = QLabel(tr("settings.ti.shodan_note"))
        shodan_note.setObjectName("hint")
        shodan_note.setWordWrap(True)
        form.addRow("", shodan_note)

        # --- Кэш ---
        sp_ttl = QSpinBox()
        sp_ttl.setRange(1, 365)
        sp_ttl.setFixedWidth(120)
        form.addRow(tr("settings.threatintel.cache_ttl"), sp_ttl)
        self._ti_inputs["enrichment_cache_ttl_days"] = sp_ttl

        le_cache = QLineEdit()
        le_cache.setMaximumWidth(420)
        form.addRow(tr("settings.threatintel.cache_path"), le_cache)
        self._ti_inputs["enrichment_cache_path"] = le_cache

        # --- Лимит IOC ---
        sp_max = QSpinBox()
        sp_max.setRange(1, 10000)
        sp_max.setFixedWidth(120)
        form.addRow(tr("settings.threatintel.max_iocs"), sp_max)
        self._ti_inputs["enrichment_max_iocs"] = sp_max

        outer.addWidget(scroll, stretch=1)
        outer.addLayout(self._make_buttons(
            self._load_threatintel, self._apply_threatintel,
        ))

        self._load_threatintel()
        return w


    def _toggle_api_keys_visibility(self, visible: bool) -> None:
        """Показать/скрыть ключи в обоих полях. Полезно, когда копируешь
        длинный ключ и хочешь убедиться, что вставилось без обрезки.
        """
        mode = (
            QLineEdit.EchoMode.Normal if visible
            else QLineEdit.EchoMode.Password
        )
        self._ti_abuse_key.setEchoMode(mode)
        self._ti_vt_key.setEchoMode(mode)
        for _w in (
            getattr(self, "_ti_abusech_key", None),
            getattr(self, "_ti_otx_key", None),
            getattr(self, "_ti_greynoise_key", None),
            getattr(self, "_ti_urlscan_key", None),
        ):
            if _w is not None:
                _w.setEchoMode(mode)


    def _load_threatintel(self) -> None:
        """Заполнить поля из Config и SecretsStore (keyring/env)."""
        try:
            from paradox.config import Config
        except ImportError:
            return
        cfg = Config()
        for key, widget in self._ti_inputs.items():
            value = getattr(cfg, key, None)
            if value is None:
                continue
            if isinstance(widget, QSpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, QLineEdit):
                widget.setText(str(value))
            elif isinstance(widget, (QPlainTextEdit, EditableListWidget)):
                if isinstance(value, (frozenset, tuple, set, list)):
                    widget.setPlainText(_format_lines(value))
        # Все ключи — через SecretsStore: keyring -> session -> env.
        self._ti_abuse_key.setText(self._secrets.get("abuseipdb_api_key"))
        self._ti_vt_key.setText(self._secrets.get("virustotal_api_key"))
        self._ti_abusech_key.setText(self._secrets.get("abusech_auth_key"))
        self._ti_otx_key.setText(self._secrets.get("otx_api_key"))
        self._ti_greynoise_key.setText(self._secrets.get("greynoise_api_key"))
        self._ti_urlscan_key.setText(self._secrets.get("urlscan_api_key"))


    def _apply_threatintel(self) -> None:
        """Сохранить ключи в keyring+env, поля Config — в config_applied."""
        key_widgets = {
            "abuseipdb_api_key": self._ti_abuse_key,
            "virustotal_api_key": self._ti_vt_key,
            "abusech_auth_key": self._ti_abusech_key,
            "otx_api_key": self._ti_otx_key,
            "greynoise_api_key": self._ti_greynoise_key,
            "urlscan_api_key": self._ti_urlscan_key,
        }
        for name, widget in key_widgets.items():
            # SecretsStore.set обновляет и keyring, и os.environ.
            self._secrets.set(name, widget.text())

        values: dict = {}
        for key, widget in self._ti_inputs.items():
            if isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QLineEdit):
                if key == "enrichment_cache_path":
                    text = widget.text().strip()
                    if text:
                        try:
                            Path(text).parent.mkdir(
                                parents=True, exist_ok=True,
                            )
                        except OSError:
                            pass
                        values[key] = Path(text)
            elif isinstance(widget, QPlainTextEdit):
                values[key] = _parse_lines(widget.toPlainText())
        self.config_applied.emit(values)
