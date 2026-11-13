"""Язык текстов ядра: отчёты, CLI, объяснения.

GUI переводит интерфейс своим словарём (`paradox_gui/i18n`); здесь
только то, что уходит в файлы отчётов и в stdout — иначе на английской
машине отчёт оставался бы русским при английском интерфейсе.

Два способа перевода, выбор осознанный:

- `L("по-русски", "in English")` — фразы внутри кода отчёта. Оба
  варианта стоят рядом, расхождение видно при чтении диффа, ключи
  заводить не нужно.
- `*_en.py` рядом с каталогом — сотни строк шаблонов объяснений, где
  пары «строка за строкой» превратили бы код в нечитаемую мешанину.

Язык по умолчанию — русский: прежние тексты и тесты не меняются, пока
не передан `--lang en` или не выбран английский в настройках GUI.
"""
from __future__ import annotations

import warnings

SUPPORTED_LANGUAGES: tuple[str, ...] = ("ru", "en")
DEFAULT_LANGUAGE: str = "ru"

_current_lang: str = DEFAULT_LANGUAGE


def set_language(lang: str) -> None:
    """Установить язык выходных текстов.

    Неизвестный код — предупреждение и no-op: опечатка в settings.json
    не должна валить прогон.
    """
    global _current_lang
    if lang in SUPPORTED_LANGUAGES:
        _current_lang = lang
    else:
        warnings.warn(
            f"paradox.i18n: unsupported language {lang!r}, "
            f"expected one of {SUPPORTED_LANGUAGES}",
            stacklevel=2,
        )


def get_language() -> str:
    return _current_lang


def is_english() -> bool:
    return _current_lang == "en"


def reset_language() -> None:
    """Вернуть русский — для тестов, чтобы порядок не влиял."""
    global _current_lang
    _current_lang = DEFAULT_LANGUAGE


def L(ru: str, en: str) -> str:
    """Выбрать вариант фразы по текущему языку."""
    return en if _current_lang == "en" else ru
