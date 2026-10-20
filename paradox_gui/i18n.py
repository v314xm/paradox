"""Простая система локализации (каркас)."""
from __future__ import annotations

TRANSLATIONS = {
    "ru": {
        "tab_run": "Прогон",
        "tab_history": "История",
        "tab_enrich": "Обогащение",
        "tab_settings": "Настройки",
        "tab_ipv6": "IPv6",
        "tab_timeline": "Таймлайн",
        "tab_export": "Экспорт",
        "menu_file": "Файл",
        "menu_tools": "Инструменты",
        "menu_help": "Помощь",
    },
    "en": {
        "tab_run": "Run",
        "tab_history": "History",
        "tab_enrich": "Enrichment",
        "tab_settings": "Settings",
        "tab_ipv6": "IPv6",
        "tab_timeline": "Timeline",
        "tab_export": "Export",
        "menu_file": "File",
        "menu_tools": "Tools",
        "menu_help": "Help",
    },
}

_current_lang = "ru"


def set_language(lang: str) -> None:
    global _current_lang
    if lang in TRANSLATIONS:
        _current_lang = lang


def get_language() -> str:
    return _current_lang


def tr(key: str) -> str:
    """Вернуть перевод по ключу."""
    return TRANSLATIONS.get(_current_lang, {}).get(key, key)
