"""Сетка из 6 плиток: Пакеты · Flows · Findings · Противоречия · Размер · Время.

Виджет тупой: получает dict — обновляет значения. Форматирование
внутри, чтобы наружу ходили только «сырые» числа (легче тестировать).
Плитка «Противоречия» подсвечивается красным только когда значение > 0.
"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

# Порядок плиток: (ключ, подпись, акцентная?).
# Ключи совпадают с report["summary"] из run_pipeline.
_TILES = (
    ("packets",         "Пакеты",        False),
    ("flows",           "Flows",         False),
    ("findings",        "Findings",      False),
    ("contradictions",  "Противоречия",  True),   # акцентная
    ("size_bytes",      "Размер",        False),
    ("duration_sec",    "Время",         False),
)


class SummaryGrid(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._value_labels: dict[str, QLabel] = {}
        self._tile_frames: dict[str, QFrame] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        # QGridLayout 2×3. На узком окне сетка не переносится, но
        # это GUI на 1280px — перенос не нужен.
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)

        for idx, (key, title, accent) in enumerate(_TILES):
            tile = self._make_tile(key, title, accent)
            self._tile_frames[key] = tile
            row, col = divmod(idx, 3)
            grid.addWidget(tile, row, col)

    def _make_tile(self, key: str, title: str, accent: bool) -> QFrame:
        frame = QFrame()
        frame.setObjectName("summaryTile")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        value = QLabel("—")
        value.setObjectName("summaryValueContra" if accent else "summaryValue")
        value.setAlignment(Qt.AlignmentFlag.AlignCenter)

        label = QLabel(title)
        label.setObjectName("muted")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(value)
        layout.addWidget(label)

        self._value_labels[key] = value
        return frame

    # ---------- публичный API ----------

    def set_values(self, summary: dict) -> None:
        """Принимает report['summary']. Отсутствующие ключи → '—'."""
        self._set_label("packets",        self._fmt_int(summary.get("packets")))
        self._set_label("flows",          self._fmt_int(summary.get("flows")))
        self._set_label("findings",       self._fmt_int(summary.get("findings")))
        self._set_label("contradictions", self._fmt_int(summary.get("contradictions")))
        self._set_label("size_bytes",     self._fmt_size(summary.get("size_bytes")))
        self._set_label("duration_sec",   self._fmt_duration(summary.get("duration_sec")))
        self._update_contra_accent(summary.get("contradictions"))

    def clear(self) -> None:
        """Сброс к состоянию «до анализа»."""
        for label in self._value_labels.values():
            label.setText("—")
        self._update_contra_accent(0)

    # ---------- внутреннее ----------

    def _set_label(self, key: str, text: str) -> None:
        self._value_labels[key].setText(text)

    def _update_contra_accent(self, count) -> None:
        # Свойство ставим и на tile, и на label: QSS-селекторы у нас плоские
        # (QFrame#summaryTile[hasContra] и QLabel#summaryValueContra[hasContra]),
        # поэтому каждому виджету нужен свой property + repolish.
        has_contra = bool(count)
        for w in (self._tile_frames["contradictions"], self._value_labels["contradictions"]):
            w.setProperty("hasContra", has_contra)
            w.style().unpolish(w)
            w.style().polish(w)
            w.update()

    # ---------- форматирование ----------

    @staticmethod
    def _fmt_int(v) -> str:
        if v is None:
            return "—"
        # Пробел как разделитель тысяч — читается лучше запятой в UI.
        return f"{int(v):,}".replace(",", " ")

    @staticmethod
    def _fmt_size(v) -> str:
        if v is None:
            return "—"
        size = float(v)
        for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
            if size < 1024:
                # Без дробной части для байт и КБ, одна для МБ+.
                if unit in ("Б", "КБ"):
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} ПБ"

    @staticmethod
    def _fmt_duration(v) -> str:
        if v is None:
            return "—"
        sec = float(v)
        if sec < 60:
            return f"{sec:.1f} сек"
        m, s = divmod(int(sec), 60)
        return f"{m} мин {s} сек"
