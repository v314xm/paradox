"""Безопасный статический предпросмотр payload'а.

Задача: показать, как выглядит разметка из тела запроса/ответа, не
исполняя и не загружая ничего. Одного QTextBrowser мало: он не умеет
JavaScript, но payload может тянуть картинку-маячок, подменить
интерфейс формой входа или растянуть окно. Поэтому разметку чистим
ДО рендера:

  - белый список тегов и атрибутов;
  - script/style/head/iframe/object/embed/form/input/meta/link/img
    вырезаются вместе с содержимым;
  - ссылки и src не сохраняются вообще;
  - серверный код не исполняется: из PHP/ASP-блока берутся только
    строковые литералы с разметкой (так веб-шелл показывает свою
    страницу), остальное заменяется плейсхолдером;
  - из multipart/form-data показывается тело части с файлом, а не
    MIME-обёртка запроса.

Результат — обычная строка HTML для QTextBrowser.
"""
from __future__ import annotations

import html
import re
from html.parser import HTMLParser

#: Больше этого разметку не рендерим: патологические таблицы вешают
#: раскладку, а выдержка и так ограничена ядром.
_MAX_OUTPUT = 200_000

_ALLOWED_TAGS = frozenset({
    "p", "div", "span", "br", "hr", "b", "strong", "i", "em", "u", "s",
    "sub", "sup", "table", "thead", "tbody", "tfoot", "tr", "td", "th",
    "caption", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "pre", "code", "blockquote", "center", "small", "big",
})

#: Содержимое этих тегов не показываем вовсе.
_DROP_CONTENT = frozenset({"script", "style", "head", "title", "template"})

#: Теги без закрывающего.
_VOID_TAGS = frozenset({"br", "hr"})

_ALLOWED_ATTRS = frozenset({
    "colspan", "rowspan", "align", "valign", "border",
    "cellpadding", "cellspacing",
})

_PHP_RE = re.compile(r"<\?(?:php\b)?(.*?)(?:\?>|$)", re.S | re.I)
_ASP_RE = re.compile(r"<%(.*?)(?:%>|$)", re.S)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_STRING_RE = re.compile(
    r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", re.S,
)
_BOUNDARY_RE = re.compile(r"^--[^\n]*\n?", re.M)
_FORM_DATA_RE = re.compile(r"^content-disposition:\s*form-data", re.M | re.I)

_PLACEHOLDER = "{ серверный код }"
_HEADER_SEP_RE = re.compile(r"\r?\n\r?\n")


def _decode(data: bytes) -> str:
    for encoding in ("utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("iso-8859-1", errors="replace")


def _multipart_payload(text: str) -> str:
    """Тело частей multipart/form-data без MIME-шапки и границ.

    Выдержка — это всё тело запроса: аналитику нужен загруженный файл,
    а не строки вида «Content-Disposition» и разделители.
    """
    if not _FORM_DATA_RE.search(text):
        return text

    bodies: list[str] = []
    for part in _BOUNDARY_RE.split(text):
        match = _HEADER_SEP_RE.search(part)
        if match is None:
            continue
        headers = part[:match.start()]
        if not _FORM_DATA_RE.search(headers):
            continue
        body = part[match.end():].rstrip("\r\n")
        if body:
            bodies.append(body)

    if not bodies:
        return text
    markup = [body for body in bodies if "<" in body and ">" in body]
    return "\n".join(markup or bodies)


def _markup_from_code(code: str) -> str:
    """Разметка из строковых литералов серверного кода.

    Веб-шеллы собирают страницу из `echo '<html>…'`, поэтому в самом
    литерале лежит безопасная статика. Код вне строк не показываем:
    вызовы вроде командной оболочки в предпросмотр не попадают.
    """
    out: list[str] = []
    for match in _STRING_RE.finditer(code):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        value = (
            value
            .replace("\\'", "'")
            .replace('\\"', '"')
            .replace("\\\\", "\\")
        )
        if "<" in value and ">" in value:
            out.append(value)
    return "".join(out)


def _server_block(code: str) -> str:
    markup = _markup_from_code(code)
    return markup or _PLACEHOLDER


class _Sanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._out: list[str] = []
        self._size = 0
        self._drop_depth = 0
        self._open: list[str] = []

    # ------------------------------------------------------------ API

    def result(self) -> str:
        while self._open:
            self._out.append(f"</{self._open.pop()}>")
        return "".join(self._out)

    # -------------------------------------------------- HTMLParser hooks

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _DROP_CONTENT:
            self._drop_depth += 1
            return
        if self._drop_depth or tag not in _ALLOWED_TAGS:
            return
        if tag in _VOID_TAGS:
            self._emit(f"<{tag}/>")
            return
        self._open.append(tag)
        self._emit(f"<{tag}{self._attrs(attrs)}>")

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self._drop_depth or tag not in _ALLOWED_TAGS:
            return
        self._emit(f"<{tag}{self._attrs(attrs)}/>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _DROP_CONTENT:
            self._drop_depth = max(0, self._drop_depth - 1)
            return
        if self._drop_depth or tag in _VOID_TAGS:
            return
        if tag not in self._open:
            return
        # Закрываем всё, что открыто внутри: несбалансированная
        # разметка payload'а не должна ломать документ предпросмотра.
        while self._open:
            current = self._open.pop()
            self._emit(f"</{current}>")
            if current == tag:
                break

    def handle_data(self, data):
        if self._drop_depth or not data:
            return
        self._emit(html.escape(data, quote=False))

    # --------------------------------------------------------- внутреннее

    def _attrs(self, attrs) -> str:
        parts = []
        for name, value in attrs:
            name = (name or "").lower()
            if name not in _ALLOWED_ATTRS or value is None:
                continue
            parts.append(f' {name}="{html.escape(value, quote=True)}"')
        return "".join(parts)

    def _emit(self, chunk: str) -> None:
        if self._size >= _MAX_OUTPUT:
            return
        self._size += len(chunk)
        self._out.append(chunk)


def render_safe_html(raw: bytes | str) -> str:
    """Санитизированная разметка payload'а для статического предпросмотра."""
    text = _decode(raw) if isinstance(raw, (bytes, bytearray)) else raw
    text = _CTRL_RE.sub("", text)
    text = _multipart_payload(text)
    # BOM остаётся видимым мусором в начале страницы: в UTF-8 он
    # декодируется в \ufeff, а в дважды закодированном виде — «ï»¿».
    text = text.removeprefix("\ufeff").removeprefix("ï»¿")
    text = _PHP_RE.sub(lambda m: _server_block(m.group(1)), text)
    text = _ASP_RE.sub(lambda m: _server_block(m.group(1)), text)
    if not text.strip():
        return ""

    parser = _Sanitizer()
    parser.feed(text[:_MAX_OUTPUT])
    parser.close()
    document = parser.result()
    # Без тегов это обычный текст (команда, код, лог): сохраняем
    # переносы, иначе QTextBrowser схлопывает всё в один абзац.
    if document and "<" not in document:
        return f"<pre>{document}</pre>"
    return document
