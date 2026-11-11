"""Окно «Код инжекта» — рабочее место по payload'у.

Детекторы инъекций и веб-шеллов кладут в evidence найденных
findings запись `payload_samples`: выдержки тел в base64. Здесь они
превращаются в инструмент: поиск, hex-страницы, части multipart,
безопасная деобфускация, копирование/сохранение, инспектор с IOC и
вложенными файлами.

Безопасность:
  - payload никогда не исполняется и не рендерится как HTML;
  - управляющие байты показываются значками;
  - запись на диск — только явной кнопкой;
  - ссылки и внешние ресурсы в предпросмотре вырезаны.
"""
from __future__ import annotations

import base64
import hashlib
import html
import os
from dataclasses import dataclass, field

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QKeySequence,
    QShortcut,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from paradox.payload_analysis import PayloadAnalysis, analyze_payload
from paradox.payload_deobfuscate import deobfuscate
from paradox.payload_excerpt import decode_sample, is_text
from paradox.payload_export import build_markdown
from paradox_gui.i18n import tr
from paradox_gui.payload_decode import Variant, build_variants
from paradox_gui.payload_highlighter import PayloadHighlighter, detect_language
from paradox_gui.payload_preview import render_safe_html
from paradox_gui.theme import SEVERITY

#: Страница hexdump: 4 КБ достаточно, чтобы дойти до конца выдержки
#: несколькими «страницами» и не подвешивать виджет.
_HEX_PAGE = 4096
#: Потолок подсветки совпадений: иначе поиск по 64 КБ «&&» даёт
#: тысячи выделений и вкладка заметно тормозит.
_MAX_HIGHLIGHTS = 500
#: Сколько повторов одного payload'а показывать в инспекторе.
_MAX_OCCURRENCES = 8


@dataclass
class _Part:
    kind: str
    name: str
    filename: str
    content_type: str
    offset: int
    size: int
    sha256: str
    data: bytes
    truncated: bool

    def label(self) -> str:
        if self.kind == "file":
            return tr(
                "payload.part.file", name=self.filename or self.name or "—",
            )
        return tr("payload.part.field", name=self.name or "—")


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
    sha256: str = ""
    parts: list[_Part] = field(default_factory=list)

    @property
    def raw(self) -> bytes:
        return decode_sample({"text_b64": self.text_b64})

    def title(self) -> str:
        target = f"{self.host}{self.uri}" if self.host else self.uri
        return f"{self.finding_type} · {target or '—'}"


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _with_control_pictures(text: str) -> str:
    """Показать управляющие байты значками (␀, ␍, ␛), а не вырезать."""
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
    if variant.label:
        return variant.label
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


def _hexdump(data: bytes, offset: int = 0, limit: int = _HEX_PAGE) -> str:
    lines: list[str] = []
    end = min(len(data), offset + limit)
    for position in range(offset, end, 16):
        chunk = data[position:position + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        lines.append(f"{position:08x}  {hex_part:<47}  |{ascii_part}|")
    if len(data) > end:
        lines.append(tr(
            "payload.hex_more", shown=end, total=len(data),
        ))
    return "\n".join(lines)


class PayloadView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._payloads: list[_Payload] = []
        self._variants: list[Variant] = []
        self._current: _Payload | None = None
        self._part_index: int | None = None
        self._hex_page = 0
        self._font_size = 10
        self._analysis: PayloadAnalysis | None = None
        self._analysis_cache: dict[str, PayloadAnalysis] = {}
        self._hash_index: dict[str, list[dict]] = {}
        self._search_positions: list[tuple[int, int]] = []
        self._search_index = 0
        self._build_ui()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

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

        right_layout.addLayout(self._build_toolbar())
        right_layout.addLayout(self._build_hex_row())

        self._viewer = QPlainTextEdit()
        self._viewer.setObjectName("payloadViewer")
        self._viewer.setReadOnly(True)
        self._viewer.setUndoRedoEnabled(False)
        self._viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._highlighter = PayloadHighlighter(self._viewer.document())

        self._preview = QTextBrowser()
        self._preview.setObjectName("payloadPreview")
        self._preview.setOpenLinks(False)
        self._preview.setOpenExternalLinks(False)
        self._preview.setVisible(False)

        self._inspector = QTextBrowser()
        self._inspector.setObjectName("payloadInspector")
        self._inspector.setOpenLinks(False)
        self._inspector.setOpenExternalLinks(False)
        self._inspector.setVisible(False)

        self._code_split = QSplitter(Qt.Orientation.Horizontal)
        self._code_split.setChildrenCollapsible(False)
        self._code_split.addWidget(self._viewer)
        self._code_split.addWidget(self._preview)
        self._code_split.addWidget(self._inspector)
        self._code_split.setStretchFactor(0, 2)
        self._code_split.setStretchFactor(1, 1)
        self._code_split.setStretchFactor(2, 1)
        self._code_split.setSizes([2, 1, 1])
        right_layout.addWidget(self._code_split, stretch=1)

        self._embedded_row = QHBoxLayout()
        self._embedded_combo = QComboBox()
        self._embedded_combo.setObjectName("payloadEmbedded")
        self._save_embedded_btn = QPushButton(tr("payload.save_embedded"))
        self._save_embedded_btn.setObjectName("small")
        self._save_embedded_btn.clicked.connect(self._on_save_embedded)
        self._embedded_row.addWidget(self._embedded_combo, stretch=1)
        self._embedded_row.addWidget(self._save_embedded_btn)
        self._embedded_row_widget = QWidget()
        self._embedded_row_widget.setLayout(self._embedded_row)
        self._embedded_row_widget.setVisible(False)
        right_layout.addWidget(self._embedded_row_widget)

        self._splitter.addWidget(right)
        self._splitter.setStretchFactor(0, 0)
        self._splitter.setStretchFactor(1, 1)
        self._splitter.setSizes([320, 900])
        layout.addWidget(self._splitter, stretch=1)

        self._empty = QLabel(tr("payload.empty"))
        self._empty.setObjectName("emptyState")
        self._empty.setWordWrap(True)
        layout.addWidget(self._empty)

        shortcut = QShortcut(QKeySequence.StandardKey.Find, self)
        shortcut.activated.connect(self._focus_search)

        self.set_empty_state(True)

    def _build_toolbar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        self._search = QLineEdit()
        self._search.setObjectName("payloadSearch")
        self._search.setPlaceholderText(tr("payload.search_placeholder"))
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._on_search_changed)
        row.addWidget(self._search, stretch=1)

        self._search_case = QCheckBox(tr("payload.search_case"))
        self._search_case.toggled.connect(self._on_search_changed)
        row.addWidget(self._search_case)

        self._search_prev = QToolButton()
        self._search_prev.setText("◀")
        self._search_prev.setToolTip(tr("payload.search_prev"))
        self._search_prev.clicked.connect(lambda: self._goto_hit(-1))
        row.addWidget(self._search_prev)

        self._search_next = QToolButton()
        self._search_next.setText("▶")
        self._search_next.setToolTip(tr("payload.search_next"))
        self._search_next.clicked.connect(lambda: self._goto_hit(1))
        row.addWidget(self._search_next)

        self._search_count = QLabel("")
        self._search_count.setObjectName("hint")
        row.addWidget(self._search_count)

        self._copy_btn = QPushButton(tr("payload.copy"))
        self._copy_btn.setObjectName("small")
        self._copy_btn.setEnabled(False)
        copy_menu = self._build_copy_menu()
        self._copy_btn.setMenu(copy_menu)
        self._copy_btn.clicked.connect(self._on_copy)
        row.addWidget(self._copy_btn)

        self._save_btn = QPushButton(tr("payload.save"))
        self._save_btn.setObjectName("small")
        self._save_btn.setEnabled(False)
        self._save_btn.clicked.connect(self._on_save)
        row.addWidget(self._save_btn)

        self._export_btn = QPushButton(tr("payload.export"))
        self._export_btn.setObjectName("small")
        self._export_btn.setEnabled(False)
        self._export_btn.clicked.connect(self._on_export)
        row.addWidget(self._export_btn)

        self._hex_box = QCheckBox(tr("payload.hex"))
        self._hex_box.setEnabled(False)
        self._hex_box.toggled.connect(self._on_hex_toggled)
        row.addWidget(self._hex_box)

        self._wrap_box = QCheckBox(tr("payload.wrap"))
        self._wrap_box.toggled.connect(self._on_wrap)
        row.addWidget(self._wrap_box)

        font_down = QToolButton()
        font_down.setText("A−")
        font_down.setToolTip(tr("payload.font_down"))
        font_down.clicked.connect(lambda: self._change_font(-1))
        row.addWidget(font_down)

        font_up = QToolButton()
        font_up.setText("A+")
        font_up.setToolTip(tr("payload.font_up"))
        font_up.clicked.connect(lambda: self._change_font(1))
        row.addWidget(font_up)

        self._preview_btn = QPushButton(tr("payload.preview"))
        self._preview_btn.setObjectName("filterChip")
        self._preview_btn.setCheckable(True)
        self._preview_btn.setEnabled(False)
        self._preview_btn.setToolTip(tr("payload.preview_tooltip"))
        self._preview_btn.toggled.connect(self._on_preview_toggled)
        row.addWidget(self._preview_btn)

        self._inspector_btn = QPushButton(tr("payload.inspector"))
        self._inspector_btn.setObjectName("filterChip")
        self._inspector_btn.setCheckable(True)
        self._inspector_btn.setEnabled(False)
        self._inspector_btn.setToolTip(tr("payload.inspector_tooltip"))
        self._inspector_btn.toggled.connect(self._on_inspector_toggled)
        row.addWidget(self._inspector_btn)
        return row

    def _build_hex_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        self._parts_combo = QComboBox()
        self._parts_combo.setObjectName("payloadParts")
        self._parts_combo.setVisible(False)
        self._parts_combo.currentIndexChanged.connect(self._on_part_changed)
        row.addWidget(self._parts_combo)

        self._variant_combo = QComboBox()
        self._variant_combo.setObjectName("payloadVariant")
        self._variant_combo.setToolTip(tr("payload.variant_tooltip"))
        self._variant_combo.setEnabled(False)
        self._variant_combo.currentIndexChanged.connect(self._render)
        row.addWidget(self._variant_combo, stretch=1)

        self._hex_prev = QToolButton()
        self._hex_prev.setText("◀")
        self._hex_prev.setToolTip(tr("payload.hex_prev"))
        self._hex_prev.clicked.connect(lambda: self._change_hex_page(-1))
        self._hex_prev.setVisible(False)
        row.addWidget(self._hex_prev)

        self._hex_offset = QLabel("")
        self._hex_offset.setObjectName("mono")
        self._hex_offset.setVisible(False)
        row.addWidget(self._hex_offset)

        self._hex_next = QToolButton()
        self._hex_next.setText("▶")
        self._hex_next.setToolTip(tr("payload.hex_next"))
        self._hex_next.clicked.connect(lambda: self._change_hex_page(1))
        self._hex_next.setVisible(False)
        row.addWidget(self._hex_next)
        row.addStretch(1)
        return row

    def _build_copy_menu(self):
        menu = self._copy_btn.menu()
        if menu is None:
            menu = QMenu(self)
        actions = (
            ("payload.copy.text", self._copy_text),
            ("payload.copy.hex", self._copy_hex),
            ("payload.copy.base64", self._copy_base64),
            ("payload.copy.sha256", self._copy_sha256),
            ("payload.copy.target", self._copy_target),
        )
        for key, handler in actions:
            action = QAction(tr(key), self)
            action.triggered.connect(handler)
            menu.addAction(action)
        return menu

    # -------------------------------------------------------------- публичный

    def update_data(self, report: dict) -> None:
        """Собрать выдержки из findings отчёта."""
        self._payloads = self.collect(report)
        self._hash_index = self._index_hashes(report)
        self._list.clear()
        self._current = None
        self._analysis = None
        self._variants = []
        self._part_index = None
        self._viewer.clear()
        self._preview.clear()
        self._inspector.clear()
        self._preview.setVisible(False)
        self._inspector.setVisible(False)
        self._preview_btn.setChecked(False)
        self._preview_btn.setEnabled(False)
        self._inspector_btn.setChecked(False)
        self._inspector_btn.setEnabled(False)
        self._meta.setText("")
        self._count.setVisible(False)
        self._copy_btn.setEnabled(False)
        self._save_btn.setEnabled(False)
        self._export_btn.setEnabled(False)
        self._hex_box.setEnabled(False)
        self._parts_combo.clear()
        self._parts_combo.setVisible(False)
        self._embedded_combo.clear()
        self._embedded_row_widget.setVisible(False)
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
        self._hash_index = {}
        self._list.clear()
        self._current = None
        self._analysis = None
        self._variants = []
        self._part_index = None
        self._viewer.clear()
        self._preview.clear()
        self._inspector.clear()
        self._preview.setVisible(False)
        self._inspector.setVisible(False)
        self._preview_btn.setChecked(False)
        self._preview_btn.setEnabled(False)
        self._inspector_btn.setChecked(False)
        self._inspector_btn.setEnabled(False)
        self._meta.setText("")
        self._count.setVisible(False)
        self._copy_btn.setEnabled(False)
        self._save_btn.setEnabled(False)
        self._export_btn.setEnabled(False)
        self._hex_box.setEnabled(False)
        self._parts_combo.clear()
        self._parts_combo.setVisible(False)
        self._embedded_combo.clear()
        self._embedded_row_widget.setVisible(False)
        self._reset_variants()
        self.set_empty_state(True)

    def set_empty_state(self, empty: bool) -> None:
        self._splitter.setVisible(not empty)
        self._empty.setVisible(empty)

    def select_finding(self, finding: dict) -> int:
        """Выделить выдержку конкретной находки. -1 — выдержки нет.

        Переход из таблицы находок: строки списка собраны в порядке
        findings, поэтому ищем по паре type+value — она уникальна для
        записи отчёта и не зависит от позиции в таблице.
        """
        if not isinstance(finding, dict):
            return -1
        f_type = str(finding.get("type", ""))
        f_value = str(finding.get("value", ""))
        for row, payload in enumerate(self._payloads):
            if (payload.finding_type == f_type
                    and payload.finding_value == f_value):
                self._list.setCurrentRow(row)
                self._list.scrollToItem(self._list.item(row))
                return row
        return -1

    def analysis(self) -> PayloadAnalysis | None:
        return self._analysis

    def parts(self) -> list[_Part]:
        return list(self._current.parts) if self._current else []

    def occurrences(self) -> list[dict]:
        if self._current is None or not self._current.sha256:
            return []
        return self._hash_index.get(self._current.sha256, [])

    def current_bytes(self) -> bytes:
        return self._current_data()

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
                    sha256=str(sample.get("sha256", "")),
                    parts=_parts_of(sample),
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

    @staticmethod
    def _index_hashes(report: dict) -> dict[str, list[dict]]:
        index: dict[str, list[dict]] = {}
        if not isinstance(report, dict):
            return index
        for finding in report.get("findings", []) or []:
            evidence = finding.get("evidence") or {}
            for sample in evidence.get("payload_samples") or []:
                sha = str(sample.get("sha256", "") or "")
                if not sha:
                    continue
                index.setdefault(sha, []).append({
                    "type": str(finding.get("type", "?")),
                    "value": str(finding.get("value", "")),
                    "host": str(sample.get("host", "")),
                    "uri": str(sample.get("uri", "")),
                })
        return index

    # ------------------------------------------------------------ отрисовка

    def _on_row_changed(self, row: int) -> None:
        if not (0 <= row < len(self._payloads)):
            self._current = None
            return
        self._current = self._payloads[row]
        self._part_index = None
        self._hex_page = 0
        self._search.clear()
        data = self._current.raw
        self._copy_btn.setEnabled(True)
        self._save_btn.setEnabled(bool(data))
        self._export_btn.setEnabled(bool(data))
        self._hex_box.setEnabled(bool(data))
        self._preview_btn.setEnabled(is_text(data))
        if not is_text(data):
            self._preview_btn.setChecked(False)
        self._inspector_btn.setEnabled(True)
        self._fill_parts()
        self._prepare_variants(data)
        self._render()

    def _on_part_changed(self, index: int) -> None:
        if self._current is None:
            return
        self._part_index = None if index <= 0 else index - 1
        self._hex_page = 0
        data = self._current_data()
        self._save_btn.setEnabled(bool(data))
        self._export_btn.setEnabled(bool(data))
        self._hex_box.setEnabled(bool(data))
        self._preview_btn.setEnabled(is_text(data))
        if not is_text(data):
            self._preview_btn.setChecked(False)
        self._prepare_variants(data, keep_index=False)
        self._render()

    def _fill_parts(self) -> None:
        self._parts_combo.blockSignals(True)
        self._parts_combo.clear()
        self._parts_combo.addItem(tr("payload.part.all"))
        for part in (self._current.parts if self._current else []):
            self._parts_combo.addItem(part.label())
            self._parts_combo.setItemData(
                self._parts_combo.count() - 1,
                tr(
                    "payload.part.tooltip",
                    size=part.size,
                    offset=part.offset,
                ),
                Qt.ItemDataRole.ToolTipRole,
            )
        self._parts_combo.setCurrentIndex(0)
        self._parts_combo.setVisible(bool(self._current and self._current.parts))
        self._parts_combo.blockSignals(False)

    def _prepare_variants(
        self, data: bytes, keep_index: bool = False,
    ) -> None:
        variants = build_variants(data) if data else [Variant((), b"")]
        seen = {bytes(variant.data) for variant in variants}
        for layer in (deobfuscate(data) if data else []):
            if layer.data in seen:
                continue
            seen.add(layer.data)
            variants.append(Variant((), layer.data, label=layer.label))
        self._variants = variants
        self._fill_variants(keep_index)

    def _fill_variants(self, keep_index: bool = False) -> None:
        """Заполнить список представлений и выбрать самое разобранное."""
        previous = self._variant_combo.currentIndex()
        self._variant_combo.blockSignals(True)
        self._variant_combo.clear()
        for variant in self._variants:
            self._variant_combo.addItem(_variant_label(variant))

        if keep_index and 0 <= previous < len(self._variants):
            index = previous
        else:
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

    def _current_data(self) -> bytes:
        if self._current is None:
            return b""
        if self._part_index is not None:
            parts = self._current.parts
            if 0 <= self._part_index < len(parts):
                return parts[self._part_index].data
        return self._current.raw

    def _current_part(self) -> _Part | None:
        if self._current is None or self._part_index is None:
            return None
        parts = self._current.parts
        if 0 <= self._part_index < len(parts):
            return parts[self._part_index]
        return None

    def _render(self) -> None:
        payload = self._current
        if payload is None:
            return

        variant = self._selected_variant()
        base = self._current_data()
        data = variant.data or base
        part = self._current_part()
        self._meta.setText(self._meta_text(payload, len(data), variant))

        if self._hex_box.isChecked() or not is_text(data):
            hinted = ""
            if not is_text(data):
                hinted = tr("payload.binary_hint")
            self._viewer.setPlainText(
                (hinted + "\n" if hinted else "")
                + _hexdump(data, self._hex_page)
            )
            self._hex_controls_visible(True, data)
            self._render_preview(data, enabled=False)
            self._render_inspector(data, part)
            self._apply_selections()
            return

        plain = _normalize_newlines(_decode_text(data))
        self._viewer.setPlainText(_with_control_pictures(plain))
        self._hex_controls_visible(False, data)
        self._highlighter.set_language(detect_language(plain))
        self._render_preview(
            plain,
            enabled=self._preview_btn.isChecked()
            and not self._inspector_btn.isChecked(),
        )
        self._render_inspector(data, part)
        self._apply_selections()
        self._hint.setText(self._default_hint())

    def _hex_controls_visible(self, visible: bool, data: bytes) -> None:
        self._hex_prev.setVisible(visible)
        self._hex_next.setVisible(visible)
        self._hex_offset.setVisible(visible)
        if visible:
            total = max(len(data), 1)
            self._hex_offset.setText(
                f"0x{self._hex_page:08x} / 0x{total:08x}",
            )
            self._hex_prev.setEnabled(self._hex_page > 0)
            self._hex_next.setEnabled(self._hex_page + _HEX_PAGE < len(data))

    def _change_hex_page(self, direction: int) -> None:
        data = self._selected_variant().data or self._current_data()
        step = _HEX_PAGE * direction
        page = max(0, self._hex_page + step)
        page -= page % 16
        if data:
            page = min(page, max(0, ((len(data) - 1) // _HEX_PAGE) * _HEX_PAGE))
        self._hex_page = page
        self._render()

    def _on_hex_toggled(self, _checked: bool) -> None:
        self._hex_page = 0
        self._render()

    def _on_wrap(self, checked: bool) -> None:
        mode = (
            QPlainTextEdit.LineWrapMode.WidgetWidth
            if checked else QPlainTextEdit.LineWrapMode.NoWrap
        )
        self._viewer.setLineWrapMode(mode)

    def _change_font(self, delta: int) -> None:
        self._font_size = max(7, min(20, self._font_size + delta))
        font = self._viewer.font()
        font.setPointSize(self._font_size)
        self._viewer.setFont(font)

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

    def _render_inspector(self, data: bytes, part: _Part | None) -> None:
        key = hashlib.sha256(data).hexdigest()
        analysis = self._analysis_cache.get(key)
        if analysis is None:
            analysis = analyze_payload(data)
            self._analysis_cache[key] = analysis
        self._analysis = analysis
        self._fill_embedded(analysis)
        if not self._inspector_btn.isChecked():
            return
        self._inspector.setHtml(self._inspector_html(analysis, part))

    def _fill_embedded(self, analysis: PayloadAnalysis) -> None:
        self._embedded_combo.clear()
        for item in analysis.embedded:
            self._embedded_combo.addItem(
                tr(
                    "payload.embedded_item",
                    kind=item.kind,
                    offset=item.offset,
                ),
                item.offset,
            )
        self._embedded_row_widget.setVisible(bool(analysis.embedded))

    def _inspector_html(
        self, analysis: PayloadAnalysis, part: _Part | None,
    ) -> str:
        def block(title_key: str, body: str) -> str:
            return (
                f"<h3>{html.escape(tr(title_key))}</h3>"
                f"<div>{body}</div>"
            )

        def values(items: list[str], empty_key: str) -> str:
            if not items:
                return f"<i>{html.escape(tr(empty_key))}</i>"
            return "<br>".join(html.escape(item) for item in items[:40])

        hash_line = (
            f"SHA256: {analysis.sha256}<br>MD5: {analysis.md5}"
        )
        entropy_line = (
            f"{analysis.entropy:.3f} bits/byte"
        )
        if analysis.entropy_blocks:
            blocks = ", ".join(
                f"{value:.2f}" for _, value in analysis.entropy_blocks[:16]
            )
            entropy_line += f"<br><span>{blocks}…</span>"

        embedded = []
        for item in analysis.embedded:
            detail = ""
            if item.kind == "PE" and item.detail:
                sections = ", ".join(
                    section["name"]
                    for section in item.detail.get("sections", [])[:8]
                )
                detail = (
                    f" — {item.detail.get('magic', 'PE')}, "
                    f"{sections}"
                )
            elif item.kind == "ZIP" and item.detail:
                entries = ", ".join(item.detail.get("entries", [])[:8])
                detail = f" — {entries}"
            size = f", {item.size} B" if item.size else ""
            embedded.append(
                f"{item.kind} @ 0x{item.offset:08x}{size}{detail}"
            )

        occurrences = self.occurrences()
        occurrence_lines = [
            f"{item['type']} · {item['value']}"
            for item in occurrences[:_MAX_OCCURRENCES]
        ]

        parts = []
        if part is not None:
            parts.append(
                f"{part.label()} · "
                f"{part.content_type or '—'} · {part.size} B · "
                f"offset 0x{part.offset:08x}"
            )
        else:
            for item in analysis.parts[:16]:
                parts.append(
                    f"{item.kind}: {item.name or item.filename}"
                    f" · {item.size} B · offset 0x{item.offset:08x}"
                )

        return "".join((
            block("payload.insp.type", (
                f"{html.escape(analysis.file_kind)} · "
                f"{html.escape(analysis.mime)} · {analysis.size} B"
            )),
            block("payload.insp.hashes", hash_line),
            block("payload.insp.entropy", entropy_line),
            block(
                "payload.insp.strings",
                f"<pre>{values(analysis.strings[:30], 'payload.insp.empty')}</pre>",
            ),
            block("payload.insp.urls", values(analysis.urls, "payload.insp.empty")),
            block("payload.insp.domains", values(
                analysis.domains, "payload.insp.empty",
            )),
            block("payload.insp.ips", values(analysis.ips, "payload.insp.empty")),
            block("payload.insp.emails", values(
                analysis.emails, "payload.insp.empty",
            )),
            block("payload.insp.hashes_found", values(
                analysis.hashes, "payload.insp.empty",
            )),
            block("payload.insp.embedded", values(
                embedded, "payload.insp.empty",
            )),
            block("payload.insp.parts", values(parts, "payload.insp.empty")),
            block("payload.insp.occurrences", values(
                occurrence_lines, "payload.insp.empty",
            )),
        ))

    def _on_preview_toggled(self, checked: bool) -> None:
        if checked and self._inspector_btn.isChecked():
            self._inspector_btn.setChecked(False)
            self._inspector.setVisible(False)
        self._hint.setText(self._default_hint())
        if self._current is None:
            self._preview.setVisible(False)
            return
        self._render()

    def _on_inspector_toggled(self, checked: bool) -> None:
        if checked and self._preview_btn.isChecked():
            self._preview_btn.setChecked(False)
            self._preview.setVisible(False)
        self._inspector.setVisible(checked)
        if checked:
            self._render()
        self._hint.setText(self._default_hint())

    def _default_hint(self) -> str:
        if self._preview_btn.isChecked():
            return tr("payload.preview_hint")
        if self._inspector_btn.isChecked():
            return tr("payload.inspector_hint")
        return tr("payload.safe_hint")

    def _meta_text(
        self, payload: _Payload, shown: int, variant: Variant,
    ) -> str:
        part = self._current_part()
        if part is not None:
            head = part.label()
            detail = tr(
                "payload.part.meta",
                size=part.size,
                offset=part.offset,
            )
            if part.content_type:
                detail = f"{part.content_type} · {detail}"
            if part.truncated:
                detail += "\n" + tr(
                    "payload.part.truncated",
                    shown=len(part.data), size=part.size,
                )
        else:
            target = (
                f"{payload.host}{payload.uri}" if payload.host
                else payload.uri
            )
            parts = [
                self._direction_label(payload.direction),
                payload.method,
                target,
            ]
            head = " · ".join(p for p in parts if p)
            detail = tr("payload.meta", size=payload.size)
            if payload.content_type:
                detail = f"{payload.content_type} · {detail}"
            if payload.truncated:
                detail = f"{detail}\n" + tr(
                    "payload.truncated", shown=min(shown, payload.size),
                    size=payload.size,
                )
        if payload.sha256:
            detail = f"{detail}\nSHA256 {payload.sha256}"
        if variant.label:
            detail = f"{detail}\n" + tr(
                "payload.decoded_note", steps=variant.label,
            )
        elif variant.steps:
            chain = " → ".join(
                tr(f"payload.variant.{step}") for step in variant.steps
            )
            detail = f"{detail}\n" + tr(
                "payload.decoded_note", steps=chain,
            )
        return f"{head}\n{detail}"

    @staticmethod
    def _direction_label(direction: str) -> str:
        if direction == "response":
            return tr("payload.direction.response")
        return tr("payload.direction.request")

    # --------------------------------------------------------------- поиск

    def _focus_search(self) -> None:
        self._search.setFocus()
        self._search.selectAll()

    def _on_search_changed(self, *_args) -> None:
        term = self._search.text()
        self._search_positions = []
        self._search_index = 0
        if term:
            flags = (
                QTextDocument.FindFlag.FindCaseSensitively
                if self._search_case.isChecked()
                else QTextDocument.FindFlag(0)
            )
            cursor = QTextCursor(self._viewer.document())
            while len(self._search_positions) < _MAX_HIGHLIGHTS:
                found = self._viewer.document().find(term, cursor, flags)
                if found.isNull():
                    break
                self._search_positions.append(
                    (found.selectionStart(), found.selectionEnd()),
                )
                cursor = found
        self._search_count.setText(
            f"{len(self._search_positions)}" if term else "",
        )
        self._apply_selections()
        if self._search_positions:
            self._goto_hit(0, initial=True)

    def _goto_hit(self, delta: int, initial: bool = False) -> None:
        if not self._search_positions:
            return
        if not initial:
            self._search_index = (
                self._search_index + delta
            ) % len(self._search_positions)
        start, end = self._search_positions[self._search_index]
        cursor = QTextCursor(self._viewer.document())
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        self._viewer.setTextCursor(cursor)
        self._viewer.centerCursor()
        self._search_count.setText(
            f"{self._search_index + 1}/{len(self._search_positions)}",
        )
        self._apply_selections()

    def _apply_selections(self) -> None:
        if self._search.text() and self._search_positions:
            self._set_search_selections()
        elif self._current is not None:
            self._highlight(self._current.patterns)

    def _set_search_selections(self) -> None:
        selections = []
        fmt = QTextCharFormat()
        color = QColor(SEVERITY["medium"])
        color.setAlpha(80)
        fmt.setBackground(color)
        current_fmt = QTextCharFormat()
        current_color = QColor(SEVERITY["high"])
        current_color.setAlpha(120)
        current_fmt.setBackground(current_color)

        document = self._viewer.document()
        for index, (start, end) in enumerate(self._search_positions):
            cursor = QTextCursor(document)
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format = (
                current_fmt if index == self._search_index else fmt
            )
            selections.append(selection)
        self._viewer.setExtraSelections(selections)

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

    # ------------------------------------------------------------ действия

    def _on_copy(self) -> None:
        self._copy_text()

    def _copy_text(self) -> None:
        QApplication.clipboard().setText(self._viewer.toPlainText())
        self._flash(tr("payload.copied"))

    def _copy_hex(self) -> None:
        data = self._selected_variant().data or self._current_data()
        QApplication.clipboard().setText(data.hex())
        self._flash(tr("payload.copied"))

    def _copy_base64(self) -> None:
        data = self._selected_variant().data or self._current_data()
        QApplication.clipboard().setText(
            base64.b64encode(data).decode("ascii"),
        )
        self._flash(tr("payload.copied"))

    def _copy_sha256(self) -> None:
        data = self._selected_variant().data or self._current_data()
        QApplication.clipboard().setText(hashlib.sha256(data).hexdigest())
        self._flash(tr("payload.copied"))

    def _copy_target(self) -> None:
        payload = self._current
        if payload is None:
            return
        target = (
            f"{payload.host}{payload.uri}" if payload.host
            else payload.uri
        )
        QApplication.clipboard().setText(target)
        self._flash(tr("payload.copied"))

    def _on_save(self) -> None:
        data = self._selected_variant().data or self._current_data()
        if not data:
            return
        part = self._current_part()
        if part is not None and part.filename:
            default = os.path.basename(part.filename.replace("\\", "/"))
        else:
            default = f"{hashlib.sha256(data).hexdigest()[:16]}.bin"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("payload.save_dialog"), default
        )
        if not path:
            return
        try:
            with open(path, "wb") as handle:
                handle.write(data)
        except OSError as exc:
            self._flash(tr("payload.save_error", error=str(exc)))
            return
        self._flash(tr("payload.saved", path=path))

    def _export_markdown(self) -> str:
        payload = self._current
        if payload is None:
            return ""
        data = self._selected_variant().data or self._current_data()
        analysis = self._analysis or analyze_payload(data)
        part = self._current_part()
        meta = {
            "finding_type": payload.finding_type,
            "finding_value": payload.finding_value,
            "direction": payload.direction,
            "method": payload.method,
            "host": payload.host,
            "uri": payload.uri,
            "content_type": payload.content_type,
            "truncated": payload.truncated,
        }
        if part is not None:
            meta["content_type"] = part.content_type
            meta["truncated"] = part.truncated
        variant = self._selected_variant()
        return build_markdown(
            data=data,
            analysis=analysis,
            meta=meta,
            variant_label="" if variant.is_raw() else _variant_label(variant),
            occurrences=self.occurrences(),
        )

    def _on_export(self) -> None:
        markdown = self._export_markdown()
        if not markdown:
            return
        sha = hashlib.sha256(
            self._selected_variant().data or self._current_data(),
        ).hexdigest()[:16]
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr("payload.export_dialog"),
            f"payload_{sha}.md",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(markdown)
        except OSError as exc:
            self._flash(tr("payload.save_error", error=str(exc)))
            return
        self._flash(tr("payload.exported", path=path))

    def _on_save_embedded(self) -> None:
        data = self._selected_variant().data or self._current_data()
        offset = self._embedded_combo.currentData()
        if not data or offset is None:
            return
        analysis = self._analysis
        item = next(
            (
                candidate for candidate in (analysis.embedded if analysis else [])
                if candidate.offset == offset
            ),
            None,
        )
        size = item.size if item and item.size else len(data) - offset
        chunk = data[offset:offset + max(1, size)]
        default = f"embedded_{offset:08x}.bin"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("payload.embedded_dialog"), default,
        )
        if not path:
            return
        try:
            with open(path, "wb") as handle:
                handle.write(chunk)
        except OSError as exc:
            self._flash(tr("payload.save_error", error=str(exc)))
            return
        self._flash(tr("payload.saved", path=path))

    def _flash(self, message: str) -> None:
        self._hint.setText(message)
        QTimer.singleShot(1800, lambda: self._hint.setText(self._default_hint()))

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


def _parts_of(sample: dict) -> list[_Part]:
    out: list[_Part] = []
    for item in sample.get("parts") or []:
        if not isinstance(item, dict):
            continue
        try:
            data = base64.b64decode(item.get("excerpt_b64") or "")
        except (ValueError, TypeError):
            data = b""
        out.append(_Part(
            kind=str(item.get("kind", "field")),
            name=str(item.get("name", "")),
            filename=str(item.get("filename", "")),
            content_type=str(item.get("content_type", "")),
            offset=int(item.get("offset", 0) or 0),
            size=int(item.get("size", 0) or 0),
            sha256=str(item.get("sha256", "")),
            data=data,
            truncated=bool(item.get("excerpt_truncated")),
        ))
    return out
