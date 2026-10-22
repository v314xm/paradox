"""Модалка деталей противоречия.

Открывается по кнопке «Подробнее» на карточке. Показывает полный
разбор: severity, confidence, priority, resolution_hint, facts,
likely_causes. Никаких действий с данными — только чтение dict'а
из report["contradictions"].
"""
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from paradox_gui.i18n import tr

_SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

# Веса совпадают с ядром (contradictions/base.py: SEVERITY_WEIGHT).
# Нужны для фолбэка, если priority в dict нет.
_SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.5,
    "low":      0.25,
}


class ContradictionDialog(QDialog):
    def __init__(self, contra: dict, parent=None) -> None:
        super().__init__(parent)
        self._contra = contra
        rule = contra.get("rule", "?")
        subject = contra.get("subject", "—")
        self.setWindowTitle(tr("contra.title", rule=rule, subject=subject))
        self.resize(620, 560)

        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(14)

        outer.addWidget(self._build_header())
        outer.addWidget(self._section_label(tr("contra.resolution")))
        outer.addWidget(self._build_resolution())
        outer.addWidget(self._section_label(tr("contra.facts")))
        outer.addWidget(self._build_facts(), stretch=1)
        outer.addWidget(self._section_label(tr("contra.causes")))
        outer.addWidget(self._build_causes())
        outer.addLayout(self._build_footer())

    # ---------- секции ----------

    def _build_header(self) -> QWidget:
        c = self._contra
        severity = c.get("severity", "low")

        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        badge = QLabel(f"{_SEVERITY_ICON.get(severity, '')} {severity}".strip())
        badge.setObjectName(f"severityBadge_{severity}")

        conf = c.get("confidence")
        conf_txt = f"confidence {conf:.2f}" if isinstance(conf, (int, float)) else ""

        priority = c.get("priority")
        if priority is None and isinstance(conf, (int, float)):
            # Фолбэк: priority = severity × confidence. Ядро кладёт priority
            # в dict само, но если правило его не выставило — считаем тут.
            priority = conf * _SEVERITY_WEIGHT.get(severity, 0.25)
        prio_txt = f"priority {priority:.2f}" if isinstance(priority, (int, float)) else ""

        meta = "   ".join(p for p in (conf_txt, prio_txt) if p)
        meta_lbl = QLabel(meta)
        meta_lbl.setObjectName("muted")

        row.addWidget(badge)
        row.addWidget(meta_lbl)
        row.addStretch(1)
        return w

    def _build_resolution(self) -> QLabel:
        text = (
            self._contra.get("resolution_hint")
            or self._contra.get("hint")
            or tr("contra.not_specified")
        )
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        return lbl

    def _build_facts(self) -> QScrollArea:
        facts = self._contra.get("facts") or []

        container = QFrame()
        container.setObjectName("contraFacts")
        v = QVBoxLayout(container)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(4)

        if not facts:
            empty = QLabel(tr("contra.no_facts"))
            empty.setObjectName("muted")
            v.addWidget(empty)
        else:
            for f in facts:
                line = QLabel(f"· {self._fact_to_text(f)}")
                line.setObjectName("mono")
                line.setWordWrap(True)
                v.addWidget(line)
            v.addStretch(1)

        # Скролл на случай, если фактов много.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(container)
        scroll.setMinimumHeight(140)
        return scroll

    def _build_causes(self) -> QLabel:
        causes = self._contra.get("likely_causes") or []
        if not causes:
            lbl = QLabel(tr("contra.not_specified"))
            lbl.setObjectName("muted")
            return lbl
        text = "\n".join(f"•  {c}" for c in causes)
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setObjectName("muted")
        return lbl

    def _build_footer(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addStretch(1)
        close = QPushButton(tr("contra.close"))
        close.setObjectName("primary")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        return row

    # ---------- утилиты ----------

    @staticmethod
    def _section_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("h1")
        return lbl

    @staticmethod
    def _fact_to_text(fact) -> str:
        # fact бывает строкой или dict'ом — формат зависит от того,
        # как правило собрало факты.
        if isinstance(fact, str):
            return fact
        if isinstance(fact, dict):
            source = fact.get("source", "?")
            key = (
                fact.get("key")
                or fact.get("finding_type")
                or fact.get("rule")
                or "?"
            )
            parts = [f"{source} ← {key}"]
            if fact.get("value"):
                parts.append(str(fact["value"]))
            ts = fact.get("ts") or fact.get("first_seen")
            if ts:
                parts.append(f"ts={ts}")
            conf = fact.get("confidence")
            if isinstance(conf, (int, float)):
                parts.append(f"conf={conf:.2f}")
            return "  ".join(parts)
        return str(fact)
