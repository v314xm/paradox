"""
Общий conftest для всех тестов.

faulthandler.disable() — обход Windows-бага 0xC0000005 (ACCESS_VIOLATION)
в atexit-фазе pytest на Python 3.13 + PySide6.

Воспроизводится на чистом коде (проверено через `git stash`), к логике
проекта отношения не имеет. Без этого `EXIT: -1073741819` при all-passed,
что ломает CI.
"""
import faulthandler

faulthandler.disable()
