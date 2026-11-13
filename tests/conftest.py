"""
Общий conftest для всех тестов.

faulthandler.disable() — обход Windows-бага 0xC0000005 (ACCESS_VIOLATION)
в atexit-фазе pytest на Python 3.13 + PySide6.

Воспроизводится на чистом коде (проверено через `git stash`), к логике
проекта отношения не имеет. Без этого `EXIT: -1073741819` при all-passed,
что ломает CI.
"""
import faulthandler

import pytest

from paradox.i18n import reset_language

faulthandler.disable()


@pytest.fixture(autouse=True)
def _reset_core_language():
    """Язык отчётов — глобальное состояние модуля paradox.i18n.

    Без сброса тест с `--lang en` оставил бы английский всем
    последующим тестам, и падения выглядели бы случайными.
    """
    reset_language()
    yield
    reset_language()
