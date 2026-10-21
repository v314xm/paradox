"""Страж целостности словарей i18n."""
from paradox_gui.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    validate_translations,
)


def test_all_languages_cover_same_keys():
    """Никаких «забытых» ключей в одном из языков."""
    missing = validate_translations()
    assert not missing, (
        "В словарях языков разное число ключей:\n"
        + "\n".join(
            f"  {lang}: {sorted(keys)}"
            for lang, keys in missing.items()
        )
    )


def test_default_language_in_supported():
    assert DEFAULT_LANGUAGE in SUPPORTED_LANGUAGES


def test_at_least_two_languages():
    """Международность = минимум два языка."""
    assert len(SUPPORTED_LANGUAGES) >= 2


def test_tr_returns_key_for_unknown():
    """Неизвестный ключ возвращается как есть — видно, что не переведено."""
    from paradox_gui.i18n import tr
    assert tr("__definitely_not_a_real_key__") == "__definitely_not_a_real_key__"


def test_tr_substitution():
    """format-подстановка работает."""
    from paradox_gui.i18n import tr
    out = tr("app.title", version="9.9")
    assert "9.9" in out
