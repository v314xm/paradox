"""Окно «Код инжекта» — безопасный просмотр выдержек тел.

Детекторы инъекций и веб-шеллов кладут в evidence найденных
findings запись `payload_samples`: первые `payload_excerpt_bytes`
тела, на котором сработало правило, в base64.

Что важно для безопасности:
  - текст показывается в QPlainTextEdit — payload никогда не
    рендерится как HTML, картинка или ссылка и не исполняется;
  - управляющие байты показываются значками, а не доходят до виджета
    сырыми;
  - вкладка ничего не пишет на диск: base64 из отчёта декодируется
    в памяти;
  - длинный payload обрезан самим ядром, hexdump — тоже с лимитом.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from paradox.payload_excerpt import decode_sample, is_text
from paradox_gui.i18n import tr
from paradox_gui.payload_decode import Variant, build_variants
from paradox_gui.payload_highlighter import PayloadHighlighter, detect_language
from paradox_gui.payload_preview import render_safe_html
from paradox_gui.theme import SEVERITY

#: Сколько строк hexdump показывать: 256 байт на экране достаточно,
#: чтобы понять формат, и не подвешивает виджет.
_HEX_LIMIT = 256
#: Потолок подсветки совпадений: иначе поиск по 8 КБ «&&» даёт
#: тысячи выделений и вкладка заметно тормозит.
_MAX_HIGHLIGHTS = 500


@dataclass
class _Payload:
    finding_type: str
    finding_value: str
    direction: str
    method: str
    host: str
    uri: str
    content_type: str
    size: int
    truncated: bool
    text_b64: str
    patterns: list[str]

    @property
    def raw(self) -> bytes:
        return decode_sample({"text_b64": self.text_b64})

    def title(self) -> str:
        target = f"{self.host}{self.uri}" if self.host else self.uri
        return f"{self.finding_type} · {target or '—'}"


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _with_control_pictures(text: str) -> str:
    """Показать управляющие байты значками (␀, ␍, ␛), а не вырезать.

    В payload'ах управляющие символы несут смысл (NUL-обрыв строки,
    вставки), и молча терять их нельзя.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch in ("\n", "\t"):
            out.append(ch)
        elif code < 32:
            out.append(chr(0x2400 + code))
        elif code == 0x7F:
            out.append("\u2421")
        else:
            out.append(ch)
    return "".join(out)


def _variant_label(variant: Variant) -> str:
    if variant.is_raw():
        return tr("payload.variant.raw")
    return " → ".join(tr(f"payload.variant.{step}") for step in variant.steps)


def _decode_text(data: bytes) -> str:
    for encoding in ("utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("iso-8859-1", errors="replace")


def _hexdump(data: bytes, limit: int = _HEX_LIMIT) -> str:
    lines: list[str] = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(tr("payload.hex_more", total=len(data)))
    return "\n".join(lines)


class PayloadView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._payloads: list[_Payload] = []
        self._variants: list[Variant] = []
        self._current: _Payload | None = None
        self._build_ui()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel(tr("payload.title"))
        title.setObjectName("h1")
        layout.addWidget(title)

        subtitle = QLabel(tr("payload.subtitle"))
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setChildrenCollapsible(False)

        left = QFrame()
        left.setObjectName("card")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(6)

        self._count = QLabel("")
        self._count.setObjectName("panelCount")
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.addWidget(self._count)
        header.addStretch(1)
        left_layout.addLayout(header)

        self._list = QListWidget()
        self._list.setObjectName("payloadList")
        self._list.currentRowChanged.connect(self._on_row_changed)
        left_layout.addWidget(self._list)
        self._splitter.addWidget(left)

        right = QFrame()
        right.setObjectName("card")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(14, 12, 14, 12)
        right_layout.setSpacing(8)

        self._meta = QLabel("")
        self._meta.setObjectName("mono")
        self._meta.setWordWrap(True)
        right_layout.addWidget(self._meta)

        self._hint = QLabel(tr("payload.safe_hint"))
        self._hint.setObjectName("hint")
        self._hint.setWordWrap(True)
        right_layout.addWidget(self._hint)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        self._copy_btn = QPushButton(tr("payload.copy"))
        self._copy_btn.setObjectName("small")
        self._copy_btn.clicked.connect(self._on_copy)
        self._copy_btn.setEnabled(False)
        row.addWidget(self._copy_btn)

        self._hex_box = QCheckBox(tr("payload.hex"))
        self._hex_box.setEnabled(False)
        self._hex_box.toggled.connect(self._render)
        row.addWidget(self._hex_box)

        self._variant_combo = QComboBox()
        self._variant_combo.setObjectName("payloadVariant")
        self._variant_combo.setToolTip(tr("payload.variant_tooltip"))
        self._variant_combo.setEnabled(False)
        self._variant_combo.currentIndexChanged.connect(self._render)
        row.addWidget(self._variant_combo)

        self._preview_btn = QPushButton(tr("payload.preview"))
        self._preview_btn.setObjectName("filterChip")
        self._preview_btn.setCheckable(True)
        self._preview_btn.setEnabled(False)
        self._preview_btn.setToolTip(tr("payload.preview_tooltip"))
        self._preview_btn.toggled.connect(self._on_preview_toggled)
        row.addWidget(self._preview_btn)
        row.addStretch(1)
        right_layout.addLayout(row)

        self._viewer = QPlainTextEdit()
        self._viewer.setObjectName("payloadViewer")
        self._viewer.setReadOnly(True)
        self._viewer.setUndoRedoEnabled(False)
        self._viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._highlighter = PayloadHighlighter(self._viewer.document())

        # Статический предпросмотр: санитизированная разметка, без
        # скриптов, форм и внешних ресурсов (см. payload_preview.py).
        self._preview = QTextBrowser()
        self._preview.setObjectName("payloadPreview")
        self._preview.setOpenLinks(False)
        self._preview.setOpenExternalLinks(False)
        self._preview.setVisible(False)

        self._code_split = QSplitter(Qt.Orientation.Horizontal)
        self._code_split.setChildrenCollapsible(False)
        self._code_split.addWidget(self._viewer)
        self._code_split.addWidget(self._preview)
        self._code_split.setStretchFactor(0, 1)
        self._code_split.setStretchFactor(1, 1)
        self._code_split.setSizes([1, 1])
        right_layout.addWidget(self._code_split, stretch=1)

        self._splitter.addWidget(right)
        self._splitter.setStretchFactor(0, 0)
        self._splitter.setStretchFactor(1, 1)
        self._splitter.setSizes([320, 900])
        layout.addWidget(self._splitter, stretch=1)

        self._empty = QLabel(tr("payload.empty"))
        self._empty.setObjectName("emptyState")
        self._empty.setWordWrap(True)
        layout.addWidget(self._empty)

        self.set_empty_state(True)

    # -------------------------------------------------------------- публичный

    def update_data(self, report: dict) -> None:
        """Собрать выдержки из findings отчёта."""
        self._payloads = self.collect(report)
        self._list.clear()
        self._current = None
        self._variants = []
        self._viewer.clear()
        self._preview.clear()
        self._preview.setVisible(False)
        self._preview_btn.setChecked(False)
        self._preview_btn.setEnabled(False)
        self._meta.setText("")
        self._copy_btn.setEnabled(False)
        self._hex_box.setEnabled(False)
        self._reset_variants()

        for payload in self._payloads:
            item = QListWidgetItem(payload.title())
            item.setToolTip(
                tr(
                    "payload.item_tooltip",
                    direction=self._direction_label(payload.direction),
                    size=payload.size,
                )
            )
            self._list.addItem(item)

        has_items = bool(self._payloads)
        self._count.setText(str(len(self._payloads)))
        self._count.setVisible(has_items)
        self.set_empty_state(not has_items)
        if has_items:
            self._list.setCurrentRow(0)

    def clear(self) -> None:
        self._payloads = []
        self._list.clear()
        self._current = None
        self._variants = []
        self._viewer.clear()
        self._preview.clear()
        self._preview.setVisible(False)
        self._preview_btn.setChecked(False)
        self._preview_btn.setEnabled(False)
        self._meta.setText("")
        self._count.setVisible(False)
        self._copy_btn.setEnabled(False)
        self._hex_box.setEnabled(False)
        self._reset_variants()
        self.set_empty_state(True)

    def set_empty_state(self, empty: bool) -> None:
        self._splitter.setVisible(not empty)
        self._empty.setVisible(empty)

    # --------------------------------------------------------------- сбор

    @staticmethod
    def collect(report: dict) -> list[_Payload]:
        """Выдержки из evidence всех findings, в порядке отчёта."""
        out: list[_Payload] = []
        if not isinstance(report, dict):
            return out

        for finding in report.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            evidence = finding.get("evidence") or {}
            if not isinstance(evidence, dict):
                continue

            patterns = _patterns_of(evidence)
            for sample in evidence.get("payload_samples") or []:
                if not isinstance(sample, dict):
                    continue
                b64 = sample.get("text_b64") or ""
                if not b64:
                    continue
                out.append(_Payload(
                    finding_type=str(finding.get("type", "?")),
                    finding_value=str(finding.get("value", "")),
                    direction=str(sample.get("direction", "")),
                    method=str(sample.get("method", "")),
                    host=str(sample.get("host", "")),
                    uri=str(sample.get("uri", "")),
                    content_type=str(sample.get("content_type", "")),
                    size=int(sample.get("size", 0) or 0),
                    truncated=bool(sample.get("truncated")),
                    text_b64=b64,
                    patterns=patterns,
                ))

            # Совместимость: старые отчёты хранят только 200-символьные
            # body_samples открытым текстом.
            if not evidence.get("payload_samples"):
                for text in evidence.get("body_samples") or []:
                    if not isinstance(text, str) or not text:
                        continue
                    out.append(_Payload(
                        finding_type=str(finding.get("type", "?")),
                        finding_value=str(finding.get("value", "")),
                        direction="request",
                        method=_first(evidence.get("methods")),
                        host=_first(evidence.get("hosts")),
                        uri=str(evidence.get("uri", "")),
                        content_type="",
                        size=len(text),
                        truncated=True,
                        text_b64=base64.b64encode(
                            text.encode("iso-8859-1", errors="replace")
                        ).decode("ascii"),
                        patterns=patterns,
                    ))
                    break

        return out

    # ------------------------------------------------------------ отрисовка

    def _on_row_changed(self, row: int) -> None:
        if not (0 <= row < len(self._payloads)):
            self._current = None
            return
        self._current = self._payloads[row]
        self._copy_btn.setEnabled(True)
        data = self._current.raw
        self._hex_box.setEnabled(bool(data))
        self._variants = build_variants(data) if data else []
        self._fill_variants()
        text_sample = is_text(data)
        self._preview_btn.setEnabled(text_sample)
        if not text_sample:
            self._preview_btn.setChecked(False)
        self._render()

    def _fill_variants(self) -> None:
        """Заполнить список представлений и выбрать самое разобранное."""
        self._variant_combo.blockSignals(True)
        self._variant_combo.clear()
        for variant in self._variants:
            self._variant_combo.addItem(_variant_label(variant))

        index = 0
        for i in range(len(self._variants) - 1, -1, -1):
            if is_text(self._variants[i].data):
                index = i
                break
        self._variant_combo.setCurrentIndex(index)
        self._variant_combo.blockSignals(False)
        self._variant_combo.setEnabled(len(self._variants) > 1)

    def _reset_variants(self) -> None:
        self._variant_combo.blockSignals(True)
        self._variant_combo.clear()
        self._variant_combo.blockSignals(False)
        self._variant_combo.setEnabled(False)

    def _selected_variant(self) -> Variant:
        index = self._variant_combo.currentIndex()
        if 0 <= index < len(self._variants):
            return self._variants[index]
        return Variant((), b"")

    def _render(self) -> None:
        payload = self._current
        if payload is None:
            return

        variant = self._selected_variant()
        data = variant.data or payload.raw
        self._meta.setText(self._meta_text(payload, len(data), variant.steps))

        if self._hex_box.isChecked() or not is_text(data):
            hinted = ""
            if not is_text(data):
                hinted = tr("payload.binary_hint")
            self._viewer.setPlainText(
                (hinted + "\n" if hinted else "") + _hexdump(data)
            )
            self._render_preview(data, enabled=False)
            return

        plain = _normalize_newlines(_decode_text(data))
        text = _with_control_pictures(plain)
        self._viewer.setPlainText(text)
        self._highlighter.set_language(detect_language(text))
        self._highlight(payload.patterns)
        # В предпросмотр отдаём текст без значков управляющих байт:
        # там нужна разметка, а не ␀/␍.
        self._render_preview(
            plain,
            enabled=self._preview_btn.isChecked(),
        )
        self._hint.setText(self._default_hint())

    def _render_preview(self, payload, enabled: bool) -> None:
        """Статический предпросмотр разметки в правой половине."""
        if not enabled:
            self._preview.setVisible(False)
            return

        self._preview.setVisible(True)
        document = render_safe_html(payload)
        if not document:
            self._preview.setHtml(
                f"<p>{tr('payload.preview_empty')}</p>"
            )
        else:
            self._preview.setHtml(document)

    def _on_preview_toggled(self, _checked: bool) -> None:
        self._hint.setText(self._default_hint())
        if self._current is None:
            self._preview.setVisible(False)
            return
        self._render()

    def _default_hint(self) -> str:
        if self._preview_btn.isChecked():
            return tr("payload.preview_hint")
        return tr("payload.safe_hint")

    def _meta_text(
        self, payload: _Payload, shown: int, steps: tuple[str, ...] = (),
    ) -> str:
        target = f"{payload.host}{payload.uri}" if payload.host else payload.uri
        parts = [
            self._direction_label(payload.direction),
            payload.method,
            target,
        ]
        head = " · ".join(p for p in parts if p)
        detail = tr("payload.meta", size=payload.size)
        if payload.content_type:
            detail = f"{payload.content_type} · {detail}"
        if steps:
            chain = " → ".join(tr(f"payload.variant.{s}") for s in steps)
            detail = f"{detail}\n" + tr("payload.decoded_note", steps=chain)
        if payload.truncated:
            detail = f"{detail}\n" + tr(
                "payload.truncated", shown=min(shown, payload.size),
                size=payload.size,
            )
        return f"{head}\n{detail}"

    @staticmethod
    def _direction_label(direction: str) -> str:
        if direction == "response":
            return tr("payload.direction.response")
        return tr("payload.direction.request")

    def _highlight(self, patterns: list[str]) -> None:
        """Подсветить найденные детектором фрагменты."""
        selections = []
        fmt = QTextCharFormat()
        color = QColor(SEVERITY["medium"])
        color.setAlpha(70)
        fmt.setBackground(color)
        fmt.setFontWeight(QFont.Weight.Bold)

        document = self._viewer.document()
        for pattern in patterns:
            if not pattern:
                continue
            cursor = QTextCursor(document)
            last_start = -1
            while len(selections) < _MAX_HIGHLIGHTS:
                found = document.find(pattern, cursor)
                if found.isNull():
                    break
                # Защита от зацикливания, если find вернул то же место.
                if found.selectionStart() == last_start:
                    cursor.setPosition(found.selectionEnd())
                    continue
                last_start = found.selectionStart()
                cursor = found
                selection = QTextEdit.ExtraSelection()
                selection.cursor = found
                selection.format = fmt
                selections.append(selection)
            if len(selections) >= _MAX_HIGHLIGHTS:
                break

        self._viewer.setExtraSelections(selections)

    def _on_copy(self) -> None:
        if self._current is None:
            return
        QApplication.clipboard().setText(self._viewer.toPlainText())
        self._hint.setText(tr("payload.copied"))
        QTimer.singleShot(1500, lambda: self._hint.setText(self._default_hint()))

    # ------------------------------------------------------- доступ для тестов

    def payloads(self) -> list[_Payload]:
        return list(self._payloads)

    def viewer(self) -> QPlainTextEdit:
        return self._viewer


def _first(values) -> str:
    return str(values[0]) if values else ""


def _patterns_of(evidence: dict) -> list[str]:
    """Фрагменты, которые подсветить: паттерны, маркер, семейство."""
    out: list[str] = []
    for pattern in evidence.get("matched_patterns") or []:
        if isinstance(pattern, str) and pattern:
            out.append(pattern)
    marker = evidence.get("marker")
    if isinstance(marker, str) and marker:
        out.extend(p.strip() for p in marker.split("+") if p.strip())
    return out
