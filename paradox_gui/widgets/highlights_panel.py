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

from PySide6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
)

from paradox_gui.formatting import fmt_bytes as _fmt_bytes
from paradox_gui.i18n import tr

# Больше шести карточек — это уже вторая таблица, а панель должна
# оставаться обзорной: «заметить», а не «изучить».
_MAX_CARDS = 6

_KIND_TITLES = {
    "http": "HTTP",
    "flow": "FLOW",
    "ext": "EXT",
    "finding": "FINDING",
    "contra": "CONTRA",
    "upload": "UPLOAD",
    "download": "DOWNLOAD",
    "dns": "DNS",
}

#: Чип → какие виды карточек он показывает. None — все.
_CHIP_GROUPS: dict[str | None, tuple[str, ...] | None] = {
    None: None,
    "finding": ("finding",),
    "contra": ("contra",),
    "volume": ("upload", "download"),
    "dns": ("dns",),
    "http": ("http",),
    "flow": ("flow",),
    "ext": ("ext",),
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _tooltip(lines: list[str]) -> str:
    """Tooltip как rich text: иначе IP/URI с '<' ломают разметку."""
    return "<br>".join(html.escape(line) for line in lines if line)


def _fact_lines(facts, limit: int = 4) -> list[str]:
    out = []
    for fact in facts or []:
        if not isinstance(fact, dict):
            continue
        out.append(
            f"{fact.get('source', '?')}: {fact.get('key', '?')} = "
            f"{fact.get('value', '?')}"
        )
        if len(out) >= limit:
            break
    return out


def _contradiction_entries(report: dict) -> list[dict]:
    """Самое серьёзное противоречие — первым: это и есть «почему важно»."""
    items = [
        c for c in (report.get("contradictions") or [])
        if isinstance(c, dict)
    ]
    if not items:
        return []
    items.sort(key=lambda c: (
        _SEVERITY_RANK.get(str(c.get("severity", "")).lower(), 5),
        -(c.get("confidence") or 0),
    ))
    c = items[0]
    severity = str(c.get("severity") or "?")
    subject = str(c.get("subject") or "?")
    rule = str(c.get("rule") or "")
    hint = str(c.get("resolution_hint") or "")
    confidence = c.get("confidence")
    return [{
        "kind": "contra",
        "primary": subject,
        "secondary": f"{severity.upper()} · {hint or rule}",
        "metric": f"{confidence:.2f}" if isinstance(
            confidence, (int, float)
        ) else "",
        "copy_value": subject,
        "contradiction": c,
        "tooltip": [
            f"{severity.upper()} · {rule}",
            subject,
            hint,
            *_fact_lines(c.get("facts")),
        ],
    }]


def _finding_entries(report: dict) -> list[dict]:
    """Две находки с наибольшей уверенностью."""
    items = [
        f for f in (report.get("findings") or [])
        if isinstance(f, dict)
    ]
    items.sort(key=lambda f: -(f.get("confidence") or 0))

    entries = []
    for f in items[:2]:
        f_type = str(f.get("type") or "?")
        value = str(f.get("value") or "")
        confidence = f.get("confidence")
        mitre = f.get("mitre_techniques") or ()
        if isinstance(mitre, str):
            mitre = (mitre,)
        mitre = tuple(str(t) for t in mitre)
        src = f.get("src_ip")
        dst = f.get("dst_ip")
        metric = (
            f"{confidence:.2f}" if isinstance(confidence, (int, float)) else ""
        )
        entries.append({
            "kind": "finding",
            "primary": value or f_type,
            "secondary": f_type + (f" · {mitre[0]}" if mitre else ""),
            "metric": metric,
            "copy_value": value,
            "finding": f,
            "tooltip": [
                f_type,
                value,
                f"confidence: {metric}" if metric else "",
                f"MITRE: {', '.join(mitre)}" if mitre else "",
                f"{src} → {dst}" if src and dst else "",
            ],
        })
    return entries


def _volume_entries(entities: dict) -> list[dict]:
    """Хост с самым большим переносом: отправка или скачивание."""
    internal = [
        e for e in (entities.get("internal") or [])
        if isinstance(e, dict) and e.get("ip")
    ]
    if not internal:
        return []
    best = max(
        internal,
        key=lambda e: max(
            int(e.get("bytes_out") or 0), int(e.get("bytes_in") or 0),
        ),
    )
    up = int(best.get("bytes_out") or 0)
    down = int(best.get("bytes_in") or 0)
    total = max(up, down)
    if total <= 0:
        return []

    upload = up >= down
    ip = str(best.get("ip"))
    roles = ", ".join(best.get("roles") or []) or "—"
    flows = int(best.get("flows_out") or 0) + int(best.get("flows_in") or 0)
    return [{
        "kind": "upload" if upload else "download",
        "primary": ip,
        "secondary": roles,
        "metric": ("↑ " if upload else "↓ ") + _fmt_bytes(total),
        "copy_value": ip,
        "host_ip": ip,
        "tooltip": [
            ip,
            f"roles: {roles}",
            f"↑ {_fmt_bytes(up)} · ↓ {_fmt_bytes(down)}",
            f"flows: {flows}",
        ],
    }]


def _dns_entries(report: dict) -> list[dict]:
    """Самый частый NXDOMAIN: домена нет, а хост его спрашивает."""
    dns = report.get("dns", {}) or {}
    items = [
        q for q in (dns.get("nxdomain") or [])
        if isinstance(q, dict) and q.get("name")
    ]
    if not items:
        return []
    top = max(items, key=lambda q: int(q.get("count") or 0))
    count = int(top.get("count") or 0)
    name = str(top.get("name"))
    return [{
        "kind": "dns",
        "primary": name,
        "secondary": tr("high.nxdomain", count=count),
        "metric": str(count),
        "copy_value": name,
        "tooltip": [name, tr("high.nxdomain", count=count)],
    }]


class _ElidedLabel(QLabel):
    """QLabel в одну строку: длинный URI не растягивает карточку.

    QLabel не умеет elide сам, а wordWrap ломает ритм карточек.
    Полный текст храним отдельно — он уходит в tooltip карточки.

    Клик по тексту должен копировать значение, но при этом нельзя
    отнимать выделение протяжкой. Поэтому клик эмитим только на
    release без выделения и без смещения мыши.
    """

    clicked = Signal()
    double_clicked = Signal()

    def __init__(self, text: str, parent=None) -> None:
        super().__init__(parent)
        self._full_text = text
        self._press_pos = None
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

    def mousePressEvent(self, event) -> None:  # noqa: N802 (Qt API)
        if event.button() == Qt.MouseButton.LeftButton:
            self._press_pos = event.position().toPoint()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 (Qt API)
        super().mouseReleaseEvent(event)
        if (
            event.button() == Qt.MouseButton.LeftButton
            and self._press_pos is not None
            and not self.selectedText()
        ):
            delta = event.position().toPoint() - self._press_pos
            if delta.manhattanLength() <= 3:
                self.clicked.emit()
        self._press_pos = None

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802 (Qt API)
        super().mouseDoubleClickEvent(event)
        if event.button() == Qt.MouseButton.LeftButton:
            self.double_clicked.emit()

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

    clicked = Signal(str)
    host_requested = Signal(str)
    finding_requested = Signal(object)
    contradiction_requested = Signal(object)

    def __init__(
        self,
        kind: str,
        primary: str,
        secondary: str,
        metric: str,
        tooltip: list[str],
        copy_value: str = "",
        host_ip: str = "",
        finding: dict | None = None,
        contradiction: dict | None = None,
    ) -> None:
        super().__init__()
        self.setObjectName("highlightCard")
        self.setProperty("kind", kind)
        self._copy_value = copy_value
        self._host_ip = host_ip
        self._finding = finding
        self._contradiction = contradiction
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        if finding is not None or contradiction is not None:
            hint = tr("high.open_hint")
        elif host_ip:
            hint = tr("high.copy_hint_host")
        else:
            hint = tr("high.copy_hint")
        self.setToolTip(_tooltip(tooltip + [hint]))

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 12, 8)
        layout.setSpacing(8)

        badge = QLabel(_KIND_TITLES.get(kind, kind.upper()))
        badge.setObjectName("highlightBadge")
        badge.setProperty("kind", kind)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
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

        for label in (self._primary, self._secondary):
            label.clicked.connect(self._emit_copy)
            label.double_clicked.connect(self._emit_open)

    # ---------- действия ----------

    def mousePressEvent(self, event) -> None:  # noqa: N802 (Qt API)
        if event.button() == Qt.MouseButton.LeftButton:
            self._emit_copy()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802 (Qt API)
        if event.button() == Qt.MouseButton.LeftButton and (
            self._finding is not None
            or self._contradiction is not None
            or self._host_ip
        ):
            self._emit_open()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def _emit_copy(self) -> None:
        if self._copy_value:
            self.clicked.emit(self._copy_value)

    def _emit_open(self) -> None:
        if self._finding is not None:
            self.finding_requested.emit(self._finding)
        elif self._contradiction is not None:
            self.contradiction_requested.emit(self._contradiction)
        elif self._host_ip:
            self.host_requested.emit(self._host_ip)

    # Доступ к содержимому нужен тестам: проверять elide по пикселям
    # неудобно, а исходные значения должны сохраняться целиком.
    def primary_text(self) -> str:
        return self._primary.full_text()

    def secondary_text(self) -> str:
        return self._secondary.full_text()

    def metric_text(self) -> str:
        return self._metric.text()

    def copy_value(self) -> str:
        return self._copy_value

    def kind(self) -> str:
        return self.property("kind") or ""


class HighlightsPanel(QFrame):
    copy_requested = Signal(str)
    host_story_requested = Signal(str)
    finding_requested = Signal(object)
    contradiction_requested = Signal(object)

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
            ("finding", tr("high.filter_findings")),
            ("contra", tr("high.filter_contra")),
            ("volume", tr("high.filter_volume")),
            ("dns", "DNS"),
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

        # Чипы показываем только для того, что реально попало на панель:
        # иначе фильтр открывал бы пустой список из-за потолка карточек.
        present = {e["kind"] for e in self._all_entries[:_MAX_CARDS]}
        for key, chip in self._chips.items():
            chip.setChecked(key is None)
            kinds = _CHIP_GROUPS.get(key)
            chip.setVisible(
                bool(self._all_entries)
                and (kinds is None or bool(present.intersection(kinds)))
            )

        if not self._all_entries:
            self._clear_cards()
            self._count.setVisible(False)
            self._empty.setText(tr("high.empty"))
            self._empty.setVisible(True)
            return

        self._empty.setVisible(False)
        self._apply_filter(animate=True)

    def clear(self) -> None:
        """Сбросить карточки перед новым прогоном."""
        self._all_entries = []
        self._filter = None
        self._clear_cards()
        self._count.setText("")
        self._count.setVisible(False)
        self._empty.setText(tr("high.empty"))
        self._empty.setVisible(True)
        for key, chip in self._chips.items():
            chip.setChecked(key is None)
            chip.setVisible(False)

    def _set_filter(self, kind: str | None) -> None:
        self._filter = kind
        for key, chip in self._chips.items():
            chip.setChecked(key == kind)
        self._apply_filter()

    def _apply_filter(self, animate: bool = False) -> None:
        kinds = _CHIP_GROUPS.get(self._filter)
        entries = [
            e for e in self._all_entries
            if kinds is None or e["kind"] in kinds
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
            card.clicked.connect(self.copy_requested.emit)
            card.host_requested.connect(self.host_story_requested.emit)
            card.finding_requested.connect(self.finding_requested.emit)
            card.contradiction_requested.connect(
                self.contradiction_requested.emit
            )
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
        # к этому моменту карточки уже нет в списке. Панель могла быть
        # и уничтожена целиком — тогда C++-объект карточки удалён, и
        # любое обращение к нему бросает RuntimeError.
        if card not in self._cards:
            return
        try:
            effect = QGraphicsOpacityEffect(card)
            card.setGraphicsEffect(effect)
            anim = QPropertyAnimation(effect, b"opacity", card)
        except RuntimeError:
            return
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

        # Порядок = приоритет: сначала то, что объясняет «почему это
        # важно», затем самые крупные разговоры. Потолок карточек
        # отрезает хвост, а не начало.
        entries: list[dict] = []
        entries += _contradiction_entries(report)
        entries += _finding_entries(report)
        entries += _volume_entries(entities)

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
                "copy_value": f"{host}{uri}",
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
                "copy_value": f"{dst}:{port}",
                "tooltip": [
                    f"{src} → {dst}:{port}",
                    f"direction: {direction}",
                    f"bytes: {size}",
                ],
            })

        entries += _dns_entries(report)

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
                "copy_value": ip,
                "host_ip": ip,
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
