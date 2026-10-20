"""Карточка одного противоречия из report["contradictions"].

Структура как в HTML-прототипе:
    [severity] rule subject                     conf 0.80
    → resolution_hint
    ┌ facts (раскрывается кликом) ────────────────┐
    │ · finding ← brute_force  10.0.1.50           │
    └──────────────────────────────────────────────┘
                                            [Подробнее]

Клик по карточке — toggle facts inline. Кнопка «Подробнее» — сигнал,
на который подпишется contradiction_dialog.py (шаг 6c).
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

# Иконки severity — Unicode, без внешних ресурсов. Прототип использует
# те же цвета (красный/оранжевый/жёлтый/зелёный).
_SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}


class ContradictionCard(QFrame):
    # object, а не dict — Signal(dict) в PySide6 работает через раз.
    details_requested = Signal(object)

    def __init__(self, contra: dict, parent=None) -> None:
        super().__init__(parent)
        self._contra = contra
        self._expanded = False
        self._facts_container: QFrame | None = None
        self._build_ui()

    # ---------- построение ----------

    def _build_ui(self) -> None:
        severity = self._contra.get("severity", "low")
        # Имя объекта определяет левую цветную полосу через QSS.
        self.setObjectName(f"cardContra{severity.capitalize()}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(6)

        layout.addLayout(self._build_header())
        layout.addWidget(self._build_hint())
        self._facts_container = self._build_facts()
        layout.addWidget(self._facts_container)
        layout.addLayout(self._build_footer())

    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        severity = self._contra.get("severity", "low")
        badge = QLabel(f"{_SEVERITY_ICON.get(severity, '')} {severity}".strip())
        badge.setObjectName(f"severityBadge_{severity}")

        rule = QLabel(self._contra.get("rule", "?"))
        rule.setObjectName("mono")
        rule.setStyleSheet("font-weight: 600;")

        subject = QLabel(self._contra.get("subject", "—"))
        subject.setObjectName("mono")
        subject.setStyleSheet("color: #5b8cff;")  # accent

        conf = self._contra.get("confidence")
        conf_text = f"conf {conf:.2f}" if isinstance(conf, (int, float)) else ""
        conf_lbl = QLabel(conf_text)
        conf_lbl.setObjectName("muted")

        # Прозрачные для мыши: клик по ним должен дойти до самой карточки
        # и переключить facts. Иначе Qt остановит клик на лейбле.
        for w in (badge, rule, subject, conf_lbl):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

        row.addWidget(badge)
        row.addWidget(rule)
        row.addWidget(subject)
        row.addStretch(1)
        row.addWidget(conf_lbl)
        return row

    def _build_hint(self) -> QLabel:
        # В ядре ключ resolution_hint; hint — fallback на случай,
        # если кто-то соберёт report вручную или в тестах.
        text = (
            self._contra.get("resolution_hint")
            or self._contra.get("hint")
            or ""
        )
        lbl = QLabel(f"→ {text}")
        lbl.setObjectName("contraHint")
        lbl.setWordWrap(True)
        lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        return lbl

    def _build_facts(self) -> QFrame:
        facts = self._contra.get("facts") or []
        container = QFrame()
        container.setObjectName("contraFacts")
        container.setVisible(False)  # изначально свёрнуто

        v = QVBoxLayout(container)
        v.setContentsMargins(10, 8, 10, 8)
        v.setSpacing(3)

        if not facts:
            empty = QLabel("Фактов нет.")
            empty.setObjectName("muted")
            v.addWidget(empty)
        else:
            for f in facts:
                v.addWidget(self._fact_line(f))

        return container

    def _fact_line(self, fact) -> QLabel:
        # fact может быть строкой или dict — зависит от версии ядра
        # и от того, как правило собрало факты.
        if isinstance(fact, str):
            text = fact
        elif isinstance(fact, dict):
            source = fact.get("source", "?")
            key = (
                fact.get("key")
                or fact.get("finding_type")
                or fact.get("rule")
                or "?"
            )
            parts = [f"{source} ← {key}"]
            value = fact.get("value")
            if value:
                parts.append(str(value))
            ts = fact.get("ts") or fact.get("first_seen")
            if ts:
                parts.append(f"ts={ts}")
            conf = fact.get("confidence")
            if isinstance(conf, (int, float)):
                parts.append(f"conf={conf:.2f}")
            text = "  ".join(parts)
        else:
            text = str(fact)

        lbl = QLabel(f"· {text}")
        lbl.setObjectName("mono")
        lbl.setWordWrap(True)
        lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        return lbl

    def _build_footer(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addStretch(1)
        btn = QPushButton("Подробнее")
        btn.setObjectName("small")
        btn.clicked.connect(lambda: self.details_requested.emit(self._contra))
        row.addWidget(btn)
        return row

    # ---------- интерактив ----------

    def mousePressEvent(self, event) -> None:
        # Кнопка «Подробнее» клик проглатывает сама — сюда он не дойдёт.
        if event.button() == Qt.MouseButton.LeftButton:
            self._expanded = not self._expanded
            self._facts_container.setVisible(self._expanded)
        super().mousePressEvent(event)
