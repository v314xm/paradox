"""Подсветка кода payload'а: язык, строки, опасные вызовы.

Отдельный слой поверх текста просмотрщика: QSyntaxHighlighter красит
ключевые слова, строки, комментарии и числа. Дополнительно красным
помечаются функции-«стоки» (`eval`, `system`, `io.popen`…), через
которые код исполняется, и оранжевым — источники ввода (`$_GET`,
`Request[`, `getParameter(`). Это не анализ, а ориентир для глаз:
что в этом payload'е исполняет и откуда берёт данные.

Подсветка ничего не исполняет и не ходит в сеть — только форматы
символов в QTextDocument.
"""
from __future__ import annotations

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat

from paradox_gui.theme import PALETTE, SEVERITY

#: Стоки — исполнение кода. Красный, жирный.
_SINKS = (
    r"\beval\s*\(", r"\bassert\s*\(", r"\bsystem\s*\(", r"\bexec\s*\(",
    r"\bshell_exec\s*\(", r"\bpassthru\s*\(", r"\bpopen\s*\(",
    r"\bio\.popen\s*\(", r"\bos\.system\s*\(", r"\bsubprocess\.",
    r"\bcreate_function\s*\(", r"\bRuntime\.getRuntime\s*\(",
    r"\bProcess\.Start\s*\(", r"\binclude\s*\(", r"\brequire\s*\(",
)

#: Источники ввода — суперглобалы и параметры запроса. Оранжевый.
_SOURCES = (
    r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE", r"\$_SERVER",
    r"\bRequest\s*\[", r"\bRequest\.Item\s*\[", r"\bgetParameter\s*\(",
    r"\brequest\.getParameter\b",
)

_KEYWORDS = {
    "php": (
        r"\b(function|return|if|else|elseif|foreach|for|while|echo|print|"
        r"class|new|public|private|protected|static|use|namespace|try|"
        r"catch|throw|isset|unset|empty|array|list|die|exit)\b",
    ),
    "lua": (
        r"\b(local|function|return|if|then|else|elseif|end|for|while|do|"
        r"repeat|until|break|in|and|or|not|nil|true|false)\b",
    ),
    "python": (
        r"\b(def|class|import|from|return|if|elif|else|for|while|try|"
        r"except|finally|with|as|lambda|pass|raise|in|is|not|and|or|"
        r"None|True|False)\b",
    ),
    "js": (
        r"\b(function|return|var|let|const|if|else|for|while|new|this|"
        r"typeof|try|catch|throw|async|await|true|false|null|undefined)\b",
    ),
    "shell": (
        r"\b(if|then|else|fi|for|done|while|do|case|esac|function|echo|"
        r"export|local|return|cd|rm|mv|cp|cat|chmod|whoami|uname)\b",
    ),
    "generic": (),
}

#: Признаки языка по содержимому (счётчики подстрок).
_LANGUAGE_HINTS = {
    "php": (("<?php", 6), ("<?=", 4), ("$_", 2), ("->", 1), ("?>", 3)),
    "lua": (("io.popen", 6), ("local ", 2), (":read(", 4), ("h:close", 4)),
    "python": (
        ("subprocess", 4), ("os.system", 4), ("import ", 2), ("def ", 2),
    ),
    "js": (
        ("function ", 2), ("var ", 2), ("document.", 2), ("eval(", 2),
    ),
    "shell": (
        ("#!/bin/", 6), ("wget ", 2), ("curl ", 2), ("chmod +x", 3),
    ),
}


def detect_language(text: str) -> str:
    """Грубое определение языка payload'а по характерным подстрокам."""
    lowered = text.lower()
    scores = {
        lang: sum(
            lowered.count(marker) * weight
            for marker, weight in hints
        )
        for lang, hints in _LANGUAGE_HINTS.items()
    }
    best = max(scores, key=scores.get)
    return best if scores[best] >= 2 else "generic"


def _format(color: str, *, bold: bool = False) -> QTextCharFormat:
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(color))
    if bold:
        fmt.setFontWeight(QFont.Weight.Bold)
    return fmt


class PayloadHighlighter(QSyntaxHighlighter):
    """Подсветка для просмотрщика: язык определяется по тексту."""

    def __init__(self, document) -> None:
        super().__init__(document)
        self._rules: list[tuple[QRegularExpression, QTextCharFormat]] = []
        self._language = ""
        self.set_language("generic")

    def language(self) -> str:
        return self._language

    def set_language(self, language: str) -> None:
        self._language = language
        self._rules = self._build_rules(language)
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:  # noqa: N802 (Qt API)
        for regex, fmt in self._rules:
            iterator = regex.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(
                    match.capturedStart(),
                    match.capturedLength(),
                    fmt,
                )

    # --------------------------------------------------------- внутреннее

    @staticmethod
    def _build_rules(language: str):
        keyword_fmt = _format(PALETTE["accent"], bold=True)
        string_fmt = _format(PALETTE["success"])
        comment_fmt = _format(PALETTE["text_muted"])
        number_fmt = _format(PALETTE["violet"])
        sink_fmt = _format(SEVERITY["critical"], bold=True)
        source_fmt = _format(SEVERITY["high"], bold=True)

        rules: list[tuple[QRegularExpression, QTextCharFormat]] = []
        for pattern in _KEYWORDS.get(language, ()):
            rules.append((QRegularExpression(pattern), keyword_fmt))
        for pattern in _SINKS:
            rules.append((QRegularExpression(pattern), sink_fmt))
        for pattern in _SOURCES:
            rules.append((QRegularExpression(pattern), source_fmt))

        # Строки: одинарные, двойные и обратные кавычки.
        rules.append((
            QRegularExpression(r"'([^'\\]|\\.)*'|\"([^\"\\]|\\.)*\""),
            string_fmt,
        ))
        rules.append((QRegularExpression(r"`[^`]*`"), string_fmt))
        # Комментарии: // … , # … , -- … , /* … */ в пределах строки.
        rules.append((QRegularExpression(r"//[^\n]*|#[^\n]*"), comment_fmt))
        rules.append((QRegularExpression(r"--[^\n]*"), comment_fmt))
        rules.append((QRegularExpression(r"/\*.*?\*/"), comment_fmt))
        rules.append((QRegularExpression(r"\b\d+(\.\d+)?\b"), number_fmt))
        return rules
