"""
HighlightsPanel — «что привлекло внимание» в виде карточек.

Раньше это была одна QLabel с HTML-буллетами: HTTP, потоки и внешние
хосты сливались в общий список, а значения из pcap подставлялись в
разметку без экранирования. Теперь каждый пункт — карточка с цветной
полосой категории, бейджем и метрикой. Текст остаётся выделяемым,
длинные значения обрезаются, полный текст уходит в tooltip.
"""
from __future__ import annotations

import html

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
)

from paradox_gui.i18n import tr

# Больше шести карточек — это уже вторая таблица, а панель должна
# оставаться обзорной: «заметить», а не «изучить».
_MAX_CARDS = 6

_KIND_TITLES = {
    "http": "HTTP",
    "flow": "FLOW",
    "ext": "EXT",
}


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _tooltip(lines: list[str]) -> str:
    """Tooltip как rich text: иначе IP/URI с '<' ломают разметку."""
    return "<br>".join(html.escape(line) for line in lines if line)


class _ElidedLabel(QLabel):
    """QLabel в одну строку: длинный URI не растягивает карточку.

    QLabel не умеет elide сам, а wordWrap ломает ритм карточек.
    Полный текст храним отдельно — он уходит в tooltip карточки.
    """

    def __init__(self, text: str, parent=None) -> None:
        super().__init__(parent)
        self._full_text = text
        self.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred,
        )
        self.setMinimumWidth(0)
        self._apply_elide()

    def full_text(self) -> str:
        return self._full_text

    def resizeEvent(self, event) -> None:  # noqa: N802 (Qt API)
        super().resizeEvent(event)
        self._apply_elide()

    def _apply_elide(self) -> None:
        width = self.width()
        if width <= 0:
            self.setText(self._full_text)
            return
        fm = self.fontMetrics()
        self.setText(
            fm.elidedText(
                self._full_text,
                Qt.TextElideMode.ElideRight,
                max(0, width - 2),
            )
        )


class _HighlightCard(QFrame):
    """Один пункт: полоса категории слева, бейдж, текст, метрика."""

    def __init__(
        self,
        kind: str,
        primary: str,
        secondary: str,
        metric: str,
        tooltip: str,
    ) -> None:
        super().__init__()
        self.setObjectName("highlightCard")
        self.setProperty("kind", kind)
        self.setToolTip(_tooltip(tooltip))

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 12, 8)
        layout.setSpacing(10)

        badge = QLabel(_KIND_TITLES.get(kind, kind.upper()))
        badge.setObjectName("highlightBadge")
        badge.setProperty("kind", kind)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedWidth(46)
        layout.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(2)

        self._primary = _ElidedLabel(primary)
        self._primary.setObjectName("highlightPrimary")
        self._primary.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        text_col.addWidget(self._primary)

        self._secondary = _ElidedLabel(secondary)
        self._secondary.setObjectName("highlightSecondary")
        self._secondary.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        text_col.addWidget(self._secondary)
        layout.addLayout(text_col, 1)

        self._metric = QLabel(metric)
        self._metric.setObjectName("highlightMetric")
        self._metric.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        layout.addWidget(self._metric, 0)

    # Доступ к содержимому нужен тестам: проверять elide по пикселям
    # неудобно, а исходные значения должны сохраняться целиком.
    def primary_text(self) -> str:
        return self._primary.full_text()

    def secondary_text(self) -> str:
        return self._secondary.full_text()

    def metric_text(self) -> str:
        return self._metric.text()

    def kind(self) -> str:
        return self.property("kind") or ""


class HighlightsPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("highPanel")
        self._cards: list[_HighlightCard] = []
        self._all_entries: list[dict] = []
        self._filter: str | None = None

        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 12, 14, 12)
        self._layout.setSpacing(6)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(8)

        title = QLabel(tr("high.title"))
        title.setObjectName("panelTitle")
        header.addWidget(title)

        self._count = QLabel("")
        self._count.setObjectName("panelCount")
        self._count.setVisible(False)
        header.addWidget(self._count)
        header.addStretch(1)
        self._layout.addLayout(header)

        self._layout.addLayout(self._build_chips())

        self._empty = QLabel("—")
        self._empty.setObjectName("highlightEmpty")
        self._empty.setWordWrap(True)
        self._layout.addWidget(self._empty)

    def _build_chips(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        self._chips: dict[str | None, QPushButton] = {}
        specs = (
            (None, tr("high.filter_all")),
            ("http", "HTTP"),
            ("flow", tr("high.filter_flow")),
            ("ext", tr("high.filter_ext")),
        )
        for key, label in specs:
            chip = QPushButton(label)
            chip.setObjectName("filterChip")
            chip.setCheckable(True)
            chip.setChecked(key is None)
            chip.clicked.connect(
                lambda _checked=False, k=key: self._set_filter(k)
            )
            row.addWidget(chip)
            self._chips[key] = chip
        row.addStretch(1)
        return row

    # ---------- публичный API ----------

    def update_report(self, report: dict) -> None:
        if not report:
            return

        self._all_entries = self._collect(report)
        self._filter = None

        present = {e["kind"] for e in self._all_entries}
        for key, chip in self._chips.items():
            chip.setChecked(key is None)
            chip.setVisible(
                bool(self._all_entries) and (key is None or key in present)
            )

        if not self._all_entries:
            self._clear_cards()
            self._count.setVisible(False)
            self._empty.setText(tr("high.empty"))
            self._empty.setVisible(True)
            return

        self._empty.setVisible(False)
        self._apply_filter(animate=True)

    def _set_filter(self, kind: str | None) -> None:
        self._filter = kind
        for key, chip in self._chips.items():
            chip.setChecked(key == kind)
        self._apply_filter()

    def _apply_filter(self, animate: bool = False) -> None:
        entries = [
            e for e in self._all_entries
            if self._filter is None or e["kind"] == self._filter
        ][:_MAX_CARDS]

        self._clear_cards()
        total = len(self._all_entries)
        self._count.setText(
            str(len(entries)) if self._filter is None
            else f"{len(entries)} / {total}"
        )
        self._count.setVisible(True)
        self._empty.setVisible(not entries)
        for index, entry in enumerate(entries):
            card = _HighlightCard(**entry)
            self._layout.addWidget(card)
            self._cards.append(card)
            if animate:
                self._schedule_fade(card, index)

    # ---------- появление ----------

    def _schedule_fade(self, card: _HighlightCard, index: int) -> None:
        # Каскад вместо одновременной вспышки: карточки читаются
        # сверху вниз, как список приоритетов.
        delay = min(index, 5) * 30
        if delay:
            QTimer.singleShot(delay, lambda c=card: self._fade_in(c))
        else:
            self._fade_in(card)

    def _fade_in(self, card: _HighlightCard) -> None:
        # Отложенный таймер мог сработать после пересборки панели:
        # к этому моменту карточки уже нет в списке.
        if card not in self._cards:
            return
        effect = QGraphicsOpacityEffect(card)
        card.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", card)
        anim.setDuration(180)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()

    # ---------- сбор данных ----------

    @staticmethod
    def _collect(report: dict) -> list[dict]:
        http = report.get("http", {}) or {}
        flows = report.get("flows", {}) or {}
        entities = report.get("entities", {}) or {}

        entries: list[dict] = []

        for u in (http.get("top_uris") or [])[:3]:
            method = str(u.get("method", "?"))
            uri = str(u.get("uri", "?"))
            host = str(u.get("host", "?"))
            src = str(u.get("src_ip", "?"))
            dst = str(u.get("dst_ip", "?"))
            port = u.get("dst_port", "?")
            size = _fmt_bytes(u.get("bytes", 0) or 0)
            entries.append({
                "kind": "http",
                "primary": f"{method} {uri}",
                "secondary": host,
                "metric": size,
                "tooltip": [
                    f"{method} {uri}",
                    f"host: {host}",
                    f"{src} → {dst}:{port}",
                    f"bytes: {size}",
                ],
            })

        for fl in (flows.get("top_by_bytes") or [])[:2]:
            src = str(fl.get("src_ip", "?"))
            dst = str(fl.get("dst_ip", "?"))
            port = fl.get("dst_port", "?")
            size = _fmt_bytes(fl.get("bytes", 0) or 0)
            direction = str(fl.get("direction", "?"))
            entries.append({
                "kind": "flow",
                "primary": f"{src} → {dst}:{port}",
                "secondary": direction,
                "metric": size,
                "tooltip": [
                    f"{src} → {dst}:{port}",
                    f"direction: {direction}",
                    f"bytes: {size}",
                ],
            })

        for e in (entities.get("external", []) or [])[:2]:
            ip = str(e.get("ip", "?"))
            roles = ", ".join(e.get("roles", []) or []) or "—"
            flows_in = e.get("flows_in", 0)
            flows_out = e.get("flows_out", 0)
            bytes_in = e.get("bytes_in", 0) or 0
            entries.append({
                "kind": "ext",
                "primary": ip,
                "secondary": roles,
                "metric": _fmt_bytes(bytes_in) if bytes_in else "",
                "tooltip": [
                    f"{ip}",
                    f"roles: {roles}",
                    f"flows in: {flows_in} · out: {flows_out}",
                    f"bytes in: {_fmt_bytes(bytes_in)}" if bytes_in else "",
                ],
            })

        return entries

    def _clear_cards(self) -> None:
        for card in self._cards:
            self._layout.removeWidget(card)
            card.setParent(None)
            card.deleteLater()
        self._cards.clear()

    # ---------- доступ для тестов ----------

    def cards(self) -> list[_HighlightCard]:
        return list(self._cards)
