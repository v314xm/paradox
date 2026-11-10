"""Часть главного окна: shortcuts."""
from __future__ import annotations

from PySide6.QtCore import Qt


class ShortcutsMixin:
    def _toggle_fullscreen(self) -> None:
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()


    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            # >>> ОСТАНОВКА <<<
            # Esc приоритетнее меню: если идёт анализ — стоп, иначе
            # не делаем ничего (модалки ловят Esc раньше главного окна,
            # так что сюда попадаем только когда модалок нет).
            if self.run_view.is_busy():
                self.run_view.stop_analysis()
                return
            # >>> /ОСТАНОВКА <<<
            return
        super().keyPressEvent(event)



_LATIN_TO_CYR = {
    "A": "Ф", "B": "И", "C": "С", "D": "В", "E": "У", "F": "А",
    "G": "П", "H": "Р", "I": "Ш", "J": "О", "K": "Л", "L": "Д",
    "M": "Ь", "N": "Т", "O": "Щ", "P": "З", "Q": "Й", "R": "К",
    "S": "Ы", "T": "Е", "U": "Г", "V": "М", "W": "Ц", "X": "Ч",
    "Y": "Н", "Z": "Я",
}


def _cyr_variant(seq: str) -> str | None:
    out, changed = [], False
    for ch in seq:
        up = ch.upper()
        if up in _LATIN_TO_CYR:
            cyr = _LATIN_TO_CYR[up]
            out.append(cyr if ch.isupper() else cyr.lower())
            changed = True
        else:
            out.append(ch)
    return "".join(out) if changed else None
