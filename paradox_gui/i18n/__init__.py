"""Локализация интерфейса Paradox.

Структура:
    paradox_gui/i18n/
        __init__.py   — публичный API (tr, set_language, get_language)
        _ru.py        — русские строки (дефолт)
        _en.py        — английские строки

Ключи плоские, с точками: "menu.file.open", "tab.run", "btn.cancel".
Подстановки — через str.format(): tr("app.title", version="1.2").

Поиск: текущий язык → "en" → "ru" → вернуть сам ключ.
Если ключа нет нигде — возвращается ключ (видно, что не переведено).

Добавление языка:
    1. Скопировать _ru.py → _xx.py, перевести значения.
    2. В _TRANSLATIONS ниже добавить "xx": _xx.STRINGS.
    3. В SUPPORTED_LANGUAGES добавить "xx".
    4. В _LANG_DISPLAY добавить отображаемое имя.
"""
from __future__ import annotations

import warnings

from paradox_gui.i18n import _en, _ru

#: Подключённые словари. Ключ — ISO-код языка.
_TRANSLATIONS: dict[str, dict[str, str]] = {
    "ru": _ru.STRINGS,
    "en": _en.STRINGS,
}

#: Порядок языков в выпадающем списке настроек.
SUPPORTED_LANGUAGES: tuple[str, ...] = ("ru", "en")

#: Дефолт при первом запуске / при отсутствии настройки.
DEFAULT_LANGUAGE: str = "ru"

#: Отображаемые имена языков (всегда на самом языке).
_LANG_DISPLAY: dict[str, str] = {
    "ru": "Русский",
    "en": "English",
}

#: Fallback-порядок, если ключа нет в текущем языке.
_FALLBACK_ORDER: tuple[str, ...] = ("en", "ru")

_current_lang: str = DEFAULT_LANGUAGE


def set_language(lang: str) -> None:
    """Установить текущий язык.

    Неизвестный код — предупреждение и no-op, чтобы опечатка
    в settings.json не валила GUI.
    """
    global _current_lang
    if lang in _TRANSLATIONS:
        _current_lang = lang
    else:
        warnings.warn(
            f"i18n: unsupported language {lang!r}, "
            f"expected one of {SUPPORTED_LANGUAGES}",
            stacklevel=2,
        )


def get_language() -> str:
    return _current_lang


def language_display_name(lang: str) -> str:
    """Имя языка для combo. Всегда на самом языке."""
    return _LANG_DISPLAY.get(lang, lang)


def tr(key: str, **kwargs: object) -> str:
    """Перевод по ключу с подстановкой kwargs.

    Если ключа нет ни в одном языке — возвращается сам ключ.
    Подстановка падает тихо: если в словаре {version}, а kwargs
    пустой — вернём строку как есть (лучше текст с {version},
    чем исключение в UI).
    """
    text = _lookup(key)
    if text is None:
        return key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text
    return text


def _lookup(key: str) -> str | None:
    cur = _TRANSLATIONS.get(_current_lang)
    if cur and key in cur:
        return cur[key]
    for lang in _FALLBACK_ORDER:
        d = _TRANSLATIONS.get(lang)
        if d and key in d:
            return d[key]
    return None


def validate_translations() -> dict[str, set[str]]:
    """Проверить, что словари языков покрывают одинаковые ключи.

    Возвращает {lang: set(missing_keys)}. Используется в тестах,
    не запускается автоматически.
    """
    all_keys = set()
    for d in _TRANSLATIONS.values():
        all_keys |= set(d.keys())

    out: dict[str, set[str]] = {}
    for lang, d in _TRANSLATIONS.items():
        missing = all_keys - set(d.keys())
        if missing:
            out[lang] = missing
    return out
