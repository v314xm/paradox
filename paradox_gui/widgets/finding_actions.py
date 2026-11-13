"""Правая колонка действий у таблицы находок.

Кнопки верхней группы работают с выбранной строкой и «проваливаются»
в инструмент: «Код инжекта» открывает выдержку тела этой находки,
«Обогащение» — её IOC. Нижняя группа — инструменты по всему отчёту.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QMenu,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
)

from paradox_gui.i18n import tr

#: Ширина колонки: длинная подпись «Копировать значение» должна влезать.
_PANEL_WIDTH = 200


class FindingActionsPanel(QFrame):
    details_requested = Signal(object)
    explanation_requested = Signal(object)
    payload_requested = Signal(object)
    enrich_requested = Signal(object)
    host_story_requested = Signal(str)
    copy_requested = Signal(str)
    graph_requested = Signal()
    attack_graph_requested = Signal()
    carved_requested = Signal()
    what_if_requested = Signal()
    reset_filter_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.setFixedWidth(_PANEL_WIDTH)
        self.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Expanding,
        )
        self._finding: dict | None = None
        self._hosts: list[str] = []
        self._has_report = False
        self._host_menu = QMenu(self)
        self._build_ui()
        self.clear()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(6)

        title = QLabel(tr("run.actions"))
        title.setObjectName("panelTitle")
        layout.addWidget(title)

        self._target_type = QLabel("")
        self._target_type.setObjectName("hint")
        self._target_type.setWordWrap(False)
        layout.addWidget(self._target_type)

        self._target = QLabel("")
        self._target.setObjectName("mono")
        self._target.setWordWrap(False)
        layout.addWidget(self._target)

        self._hint = QLabel(tr("run.act.no_selection"))
        self._hint.setObjectName("hint")
        self._hint.setWordWrap(True)
        layout.addWidget(self._hint)

        layout.addWidget(self._hline())
        layout.addWidget(self._group(tr("run.act.finding")))

        self.btn_details = self._button("run.act.details")
        self.btn_details.clicked.connect(self._on_details)
        layout.addWidget(self.btn_details)

        self.btn_explain = self._button("run.act.explain")
        self.btn_explain.setToolTip(tr("run.act.explain_tooltip"))
        self.btn_explain.clicked.connect(self._on_explain)
        layout.addWidget(self.btn_explain)

        self.btn_payload = self._button("run.act.payload")
        self.btn_payload.setToolTip(tr("run.act.payload_tooltip"))
        self.btn_payload.clicked.connect(self._on_payload)
        layout.addWidget(self.btn_payload)

        self.btn_enrich = self._button("run.act.enrich")
        self.btn_enrich.setToolTip(tr("run.act.enrich_tooltip"))
        self.btn_enrich.clicked.connect(self._on_enrich)
        layout.addWidget(self.btn_enrich)

        self.btn_host = self._button("run.act.host")
        self.btn_host.clicked.connect(self._on_host)
        layout.addWidget(self.btn_host)

        self.btn_copy = self._button("run.act.copy")
        self.btn_copy.clicked.connect(self._on_copy)
        layout.addWidget(self.btn_copy)

        layout.addWidget(self._hline())
        layout.addWidget(self._group(tr("run.act.tools")))

        self.btn_graph = self._button("run.graph")
        self.btn_graph.clicked.connect(self.graph_requested)
        layout.addWidget(self.btn_graph)

        self.btn_attack_graph = self._button("run.attack_graph")
        self.btn_attack_graph.clicked.connect(self.attack_graph_requested)
        layout.addWidget(self.btn_attack_graph)

        self.btn_files = self._button("run.files")
        self.btn_files.clicked.connect(self.carved_requested)
        layout.addWidget(self.btn_files)

        self.btn_what_if = self._button("run.what_if")
        self.btn_what_if.clicked.connect(self.what_if_requested)
        layout.addWidget(self.btn_what_if)

        self.btn_reset_filter = QPushButton(tr("run.reset_filter"))
        self.btn_reset_filter.setObjectName("filterChip")
        self.btn_reset_filter.clicked.connect(self.reset_filter_requested)
        layout.addWidget(self.btn_reset_filter)

        layout.addStretch(1)

    @staticmethod
    def _hline() -> QFrame:
        line = QFrame()
        line.setObjectName("hline")
        line.setFrameShape(QFrame.Shape.HLine)
        return line

    @staticmethod
    def _group(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("panelTitle")
        return label

    @staticmethod
    def _button(text_key: str) -> QPushButton:
        btn = QPushButton(tr(text_key))
        btn.setObjectName("small")
        btn.setEnabled(False)
        return btn

    # -------------------------------------------------------------- публичный

    def set_finding(self, finding: dict | None) -> None:
        """Показать выбранную находку и включить зависящие от неё кнопки."""
        self._finding = finding if isinstance(finding, dict) else None
        f = self._finding

        self._refresh_target()
        self._sync_hint()

        self.btn_details.setEnabled(f is not None)
        self.btn_explain.setEnabled(f is not None)
        self.btn_copy.setEnabled(bool(f and str(f.get("value", "")).strip()))
        self.btn_payload.setEnabled(self._has_payload(f))
        self.btn_enrich.setEnabled(bool(self._iocs_of(f)))

        self._hosts = self._hosts_of(f)
        self.btn_host.setEnabled(bool(self._hosts))
        self.btn_host.setText(
            f"{tr('run.act.host')} ▾" if len(self._hosts) > 1
            else tr("run.act.host")
        )
        self._host_menu.clear()
        for ip in self._hosts:
            action = self._host_menu.addAction(tr("run.act.host_ip", ip=ip))
            action.triggered.connect(
                lambda _checked=False, ip=ip:
                self.host_story_requested.emit(ip)
            )

    def set_report_flags(
        self,
        *,
        has_report: bool,
        has_attack_graph: bool,
        has_files: bool,
    ) -> None:
        """Включить инструменты по отчёту (они не зависят от строки)."""
        self._has_report = has_report
        self.btn_graph.setEnabled(has_report)
        self.btn_attack_graph.setEnabled(has_report and has_attack_graph)
        self.btn_files.setEnabled(has_report and has_files)
        self.btn_what_if.setEnabled(has_report)
        self._sync_hint()

    def set_filter_active(self, active: bool) -> None:
        self.btn_reset_filter.setVisible(active)

    def clear(self) -> None:
        self.set_finding(None)
        self.set_report_flags(
            has_report=False, has_attack_graph=False, has_files=False,
        )
        self.set_filter_active(False)

    # -------------------------------------------------------------- внутреннее

    def _sync_hint(self) -> None:
        """Подсказка «выберите строку» — только когда есть из чего выбирать."""
        self._hint.setVisible(self._finding is None and self._has_report)

    def _refresh_target(self) -> None:
        f = self._finding
        if f is None:
            self._target_type.setText("")
            self._target.setText("")
            self._target_type.setVisible(False)
            self._target.setVisible(False)
            return

        f_type = str(f.get("type", "?"))
        f_value = str(f.get("value", ""))
        self._target_type.setVisible(True)
        self._target.setVisible(True)
        self._target_type.setText(
            self._target_type.fontMetrics().elidedText(
                f_type, Qt.TextElideMode.ElideRight, _PANEL_WIDTH - 44,
            )
        )
        self._target_type.setToolTip(f"{f_type} · {f_value}")
        self._target.setText(
            self._target.fontMetrics().elidedText(
                f_value, Qt.TextElideMode.ElideMiddle, _PANEL_WIDTH - 44,
            )
        )
        self._target.setToolTip(f_value)

    @staticmethod
    def _has_payload(finding: dict | None) -> bool:
        if not isinstance(finding, dict):
            return False
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            return False
        return bool(
            evidence.get("payload_samples") or evidence.get("body_samples")
        )

    @staticmethod
    def _iocs_of(finding: dict | None) -> list[tuple[str, str]]:
        """IOC по той же выборке, что делает вкладка «Обогащение».

        Один путь разбора на две поверхности: если IOC нет в
        «Обогащении», кнопка перехода не должна обещать его.
        """
        if not isinstance(finding, dict):
            return []
        try:
            from paradox.integrations.enricher import (
                collect_iocs_from_findings,
            )
            return list(collect_iocs_from_findings([finding]))
        except ImportError:
            return []

    @staticmethod
    def _hosts_of(finding: dict | None) -> list[str]:
        if not isinstance(finding, dict):
            return []
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        hosts = [
            finding.get("src_ip") or evidence.get("src_ip"),
            finding.get("dst_ip") or evidence.get("dst_ip"),
        ]
        unique: list[str] = []
        for ip in hosts:
            if isinstance(ip, str) and ip and ip not in unique:
                unique.append(ip)
        return unique

    # ----------------------------------------------------------------- слоты

    def _on_details(self) -> None:
        if self._finding is not None:
            self.details_requested.emit(self._finding)

    def _on_explain(self) -> None:
        if self._finding is not None:
            self.explanation_requested.emit(self._finding)

    def _on_payload(self) -> None:
        if self._finding is not None:
            self.payload_requested.emit(self._finding)

    def _on_enrich(self) -> None:
        if self._finding is not None:
            self.enrich_requested.emit(self._finding)

    def _on_host(self) -> None:
        if len(self._hosts) == 1:
            self.host_story_requested.emit(self._hosts[0])
        elif self._hosts:
            self._host_menu.popup(
                self.btn_host.mapToGlobal(
                    self.btn_host.rect().bottomLeft()
                )
            )

    def _on_copy(self) -> None:
        if self._finding is None:
            return
        value = str(self._finding.get("value", "")).strip()
        if value:
            self.copy_requested.emit(value)
