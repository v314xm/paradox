"""f06: yara_match → execution в timeline.

yara_match есть в _SEVERITY_BY_TYPE (models.py), но не в
_PHASE_BY_TYPE (timeline.py) — findings попадали в фазу other с
chain_order=999, в отчёте висели в конце. YARA-сигнатура — это
execution (T1204, запуск payload'а).

_OLD содержит закрывающий маркер (пустая строка + следующая секция),
поэтому идемпотентен: после apply «carved_file» уже не соседствует
с "# Command and Control".
"""
from pathlib import Path

from tools._patcher import assert_applied, patch

NAME = "f06: timeline.py — yara_match в _PHASE_BY_TYPE"
FILES = ["paradox/timeline.py"]

_OLD = '''    # Execution
    "command_injection": "execution",
    "script_download": "execution",
    "carved_file": "execution",

    # Command and Control'''

_NEW = '''    # Execution
    "command_injection": "execution",
    "script_download": "execution",
    "carved_file": "execution",
    "yara_match": "execution",

    # Command and Control'''


def apply(root: Path) -> bool:
    return patch(root, FILES[0], _OLD, _NEW)


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], '"yara_match": "execution",')
