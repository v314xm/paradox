"""Окно объяснений находки или противоречия.

Раскладывает по блокам готовый текст ядра (`paradox/explain`): что
произошло, почему это важно, что смотреть дальше, альтернативные
интерпретации и версию «как новичку». Текст в GUI не собирается —
иначе окно, JSON и Markdown разойдутся.

Старые отчёты (история прогонов до 2026-11-12) ключа `explanation` не
содержат: `explanation_for` считает объяснение на месте тем же API.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from paradox.explain import Explanation, explanation_for
from paradox.taxonomy import MITRE_BY_TYPE, mitre_label
from paradox_gui.i18n import tr


def _is_contradiction(row: dict) -> bool:
    """Противоречие — это `rule` без `type` (так же решает ядро)."""
    return "rule" in row and "type" not in row


class ExplanationDialog(QDialog):
    def __init__(self, row: dict, parent=None) -> None:
        super().__init__(parent)
        self._row = row if isinstance(row, dict) else {}
        self._explanation = self._resolve()
        name = str(
            self._row.get("type") or self._row.get("rule") or "?"
        )
        self.setObjectName("explanationDialog")
        self.setWindowTitle(tr("explain.title", type=name))
        self.resize(720, 620)
        self.setMinimumSize(560, 420)
        self._build_ui()

    # ------------------------------------------------------------------ сборка

    def _resolve(self) -> Explanation:
        try:
            return explanation_for(self._row)
        except Exception:
            return Explanation(headline="")

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(12)
        outer.addWidget(self._build_header())
        outer.addWidget(self._build_body(), stretch=1)
        outer.addWidget(self._build_footer())

    def _build_header(self) -> QWidget:
        w = QWidget()
        col = QVBoxLayout(w)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(6)

        title = QLabel(self._target_title())
        title.setObjectName("dialogTitle")
        title.setWordWrap(True)
        col.addWidget(title)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        severity = self._row.get("severity")
        if severity:
            badge = QLabel(str(severity))
            badge.setObjectName(f"severityBadge_{severity}")
            row.addWidget(badge)

        conf = self._row.get("confidence")
        if isinstance(conf, (int, float)):
            conf_lbl = QLabel(f"confidence {conf:.2f}")
            conf_lbl.setObjectName("muted")
            row.addWidget(conf_lbl)

        phase = self._explanation.phase
        if phase:
            phase_lbl = QLabel(tr("explain.phase", phase=phase))
            phase_lbl.setObjectName("muted")
            row.addWidget(phase_lbl)

        row.addStretch(1)
        col.addLayout(row)

        # Техники — отдельной строкой с переносом: в одной строке с
        # бейджем и фазой длинный список («T1190 (Exploit Public-Facing
        # App), T1059 …») обрезался по правому краю.
        techniques = self._techniques_text()
        if techniques:
            tech_lbl = QLabel(techniques)
            tech_lbl.setObjectName("mono")
            tech_lbl.setWordWrap(True)
            col.addWidget(tech_lbl)
        return w

    def _build_body(self) -> QScrollArea:
        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(14)

        exp = self._explanation
        if not exp.headline:
            empty = QLabel(tr("explain.empty"))
            empty.setObjectName("muted")
            empty.setWordWrap(True)
            v.addWidget(empty)
        else:
            v.addWidget(self._section(tr("explain.what"), exp.headline))
            if exp.why:
                v.addWidget(self._section(tr("explain.why"), exp.why))
            if exp.next_steps:
                v.addWidget(self._next_steps_block())
            extras = self._extras_block()
            if extras is not None:
                v.addWidget(extras)
            if exp.confidence_note:
                v.addWidget(
                    self._section(
                        tr("explain.confidence"),
                        exp.confidence_note,
                        muted=True,
                    )
                )
        v.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(container)
        return scroll

    def _next_steps_block(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)
        v.addWidget(self._label(tr("explain.next"), "sectionLabel"))
        for index, step in enumerate(self._explanation.next_steps, 1):
            line = QLabel(f"{index}. {step}")
            line.setWordWrap(True)
            v.addWidget(line)
        return w

    def _extras_block(self) -> QWidget | None:
        """Чипы-переключатели и раскрываемые блоки под ними."""
        exp = self._explanation
        if not exp.beginner and not exp.alternatives:
            return None

        self._beginner_box = self._callout(
            tr("explain.beginner"), exp.beginner,
        )
        self._alternatives_box = self._callout_list(
            tr("explain.alternatives"), exp.alternatives,
        )

        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)

        chips = QHBoxLayout()
        chips.setContentsMargins(0, 0, 0, 0)
        chips.setSpacing(8)
        self.btn_beginner = self._chip("explain.toggle_beginner", exp.beginner)
        self.btn_alternatives = self._chip(
            "explain.toggle_alternatives", exp.alternatives,
        )
        if self.btn_beginner is not None:
            self.btn_beginner.toggled.connect(
                self._beginner_box.setVisible
            )
            chips.addWidget(self.btn_beginner)
        if self.btn_alternatives is not None:
            self.btn_alternatives.toggled.connect(
                self._alternatives_box.setVisible
            )
            chips.addWidget(self.btn_alternatives)
        chips.addStretch(1)

        v.addLayout(chips)
        if self.btn_beginner is not None:
            v.addWidget(self._beginner_box)
        if self.btn_alternatives is not None:
            v.addWidget(self._alternatives_box)
        return w

    def _build_footer(self) -> QDialogButtonBox:
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        box.setObjectName("dialogButtons")
        close = box.button(QDialogButtonBox.StandardButton.Close)
        close.setText(tr("explain.close"))
        close.setDefault(True)

        self.btn_copy = QPushButton(tr("explain.copy"))
        self.btn_copy.setObjectName("small")
        self.btn_copy.clicked.connect(self._on_copy)
        self.btn_copy.setEnabled(bool(self._explanation.headline))
        box.addButton(self.btn_copy, QDialogButtonBox.ButtonRole.ActionRole)

        box.rejected.connect(self.accept)
        return box

    # ------------------------------------------------------------------ части

    def _target_title(self) -> str:
        if _is_contradiction(self._row):
            name = str(self._row.get("rule") or "?")
            target = str(self._row.get("subject") or "—")
        else:
            name = str(self._row.get("type") or "?")
            target = str(self._row.get("value") or "—")
        return f"{name} — {target}"

    def _techniques_text(self) -> str:
        ftype = str(self._row.get("type") or "")
        if not ftype or ftype not in MITRE_BY_TYPE:
            return ", ".join(self._explanation.techniques)
        label = mitre_label(ftype)
        return "" if label == "—" else label

    def _chip(self, key: str, content) -> QPushButton | None:
        """Чип-переключатель; без содержимого не показывается вовсе."""
        if not content:
            return None
        btn = QPushButton(tr(key))
        btn.setObjectName("filterChip")
        btn.setCheckable(True)
        return btn

    @staticmethod
    def _label(text: str, role: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName(role)
        return lbl

    def _section(self, title: str, text: str, *, muted=False) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)
        v.addWidget(self._label(title, "sectionLabel"))
        body = QLabel(text)
        body.setWordWrap(True)
        body.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        if muted:
            body.setObjectName("muted")
        v.addWidget(body)
        return w

    def _callout(self, title: str, text: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName("detailPanel")
        v = QVBoxLayout(frame)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(4)
        v.addWidget(self._label(title, "sectionLabel"))
        body = QLabel(text)
        body.setWordWrap(True)
        v.addWidget(body)
        frame.setVisible(False)
        return frame

    def _callout_list(self, title: str, items) -> QFrame:
        frame = QFrame()
        frame.setObjectName("detailPanel")
        v = QVBoxLayout(frame)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(4)
        v.addWidget(self._label(title, "sectionLabel"))
        for item in items:
            line = QLabel(f"•  {item}")
            line.setWordWrap(True)
            v.addWidget(line)
        frame.setVisible(False)
        return frame

    # ------------------------------------------------------------------ слоты

    def _on_copy(self) -> None:
        text = self._explanation.to_markdown()
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.btn_copy.setText(tr("explain.copied"))
        QTimer.singleShot(
            1500,
            lambda: self.btn_copy.setText(tr("explain.copy")),
        )
