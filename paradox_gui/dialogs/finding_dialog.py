"""Модалка деталей одного finding'а.

Открывается двойным кликом по строке таблицы. Показывает всё, что
есть в dict'е finding'а: type, value, confidence, MITRE, evidence,
first_seen. Ничего не выдумывает — если ключа нет, строку не рисует.
"""
from PySide6.QtCore import Qt
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


class FindingDialog(QDialog):
    def __init__(self, finding: dict, parent=None) -> None:
        super().__init__(parent)
        self._finding = finding
        ftype = finding.get("type", "?")
        self.setWindowTitle(f"Finding: {ftype}")
        self.resize(600, 500)
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(12)

        outer.addWidget(self._build_header())
        outer.addWidget(self._section_label("Значение"))
        outer.addWidget(self._build_value())
        outer.addWidget(self._section_label("MITRE"))
        outer.addWidget(self._build_mitre())
        outer.addWidget(self._section_label("Почему такая уверенность"))
        outer.addWidget(self._build_confidence_reasons())
        outer.addWidget(self._section_label("Evidence"))
        outer.addWidget(self._build_evidence(), stretch=1)
        outer.addLayout(self._build_footer())

    # ---------- секции ----------

    def _build_header(self) -> QWidget:
        f = self._finding
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        type_lbl = QLabel(str(f.get("type", "?")))
        type_lbl.setObjectName("h1")

        conf = f.get("confidence")
        conf_lbl = QLabel(
            f"confidence {conf:.2f}" if isinstance(conf, (int, float)) else ""
        )
        conf_lbl.setObjectName("muted")

        ts = f.get("first_seen")
        ts_lbl = QLabel(f"first seen {self._format_ts(ts)}" if ts else "")
        ts_lbl.setObjectName("muted")

        row.addWidget(type_lbl)
        row.addWidget(conf_lbl)
        row.addWidget(ts_lbl)
        row.addStretch(1)
        return w

    def _build_value(self) -> QLabel:
        lbl = QLabel(str(self._finding.get("value", "—")))
        lbl.setWordWrap(True)
        lbl.setObjectName("mono")
        return lbl

    def _build_mitre(self) -> QLabel:
        mitre = self._finding.get("mitre_techniques") or ()
        if isinstance(mitre, str):
            mitre = (mitre,)
        text = ", ".join(mitre) if mitre else "—"
        lbl = QLabel(text)
        lbl.setObjectName("mono")
        lbl.setWordWrap(True)
        return lbl

    def _build_confidence_reasons(self) -> QWidget:
        reasons = self._finding.get("confidence_reasons") or []

        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)

        if not reasons:
            empty = QLabel("Нет детального разбора (старый детектор или нет причин).")
            empty.setObjectName("muted")
            v.addWidget(empty)
        else:
            for reason in reasons:
                lbl = QLabel(f"• {reason}")
                lbl.setObjectName("mono")
                lbl.setWordWrap(True)
                v.addWidget(lbl)

        return w

    def _build_evidence(self) -> QScrollArea:
        ev = self._finding.get("evidence") or {}

        container = QFrame()
        container.setObjectName("contraFacts")  # переиспользуем стиль
        v = QVBoxLayout(container)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(4)

        if not ev:
            empty = QLabel("Evidence пусто.")
            empty.setObjectName("muted")
            v.addWidget(empty)
        elif isinstance(ev, dict):
            for k, val in ev.items():
                line = QLabel(f"{k}: {self._compact(val)}")
                line.setObjectName("mono")
                line.setWordWrap(True)
                line.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                v.addWidget(line)
        else:
            line = QLabel(str(ev))
            line.setObjectName("mono")
            line.setWordWrap(True)
            v.addWidget(line)
        v.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(container)
        scroll.setMinimumHeight(160)
        return scroll

    def _build_footer(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addStretch(1)
        close = QPushButton("Закрыть")
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
    def _format_ts(ts) -> str:
        if ts is None:
            return "—"
        if isinstance(ts, (int, float)):
            from datetime import datetime
            try:
                return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, ValueError):
                return f"{ts:.1f}"
        return str(ts)

    @staticmethod
    def _compact(val) -> str:
        # Evidence-значения могут быть большими списками — режем до
        # первых элементов, чтобы модалка не разъехалась.
        if isinstance(val, (list, tuple)):
            head = list(val)[:5]
            tail = "" if len(val) <= 5 else f" … (+{len(val) - 5})"
            return ", ".join(str(x) for x in head) + tail
        if isinstance(val, dict):
            return str(dict(list(val.items())[:5]))
        return str(val)
