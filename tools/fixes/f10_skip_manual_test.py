"""f10: помечать test_multi_pcap.py как skip.

Файл — manual-скрипт (main + if __name__), не pytest-тест:
нет ни одного def test_*. Сейчас pytest его просто импортирует.
Явный pytestmark убирает двусмысленность.
"""
from pathlib import Path

from tools._patcher import assert_applied, patch

NAME = "f10: test_multi_pcap.py — skip"
FILES = ["tests/test_multi_pcap.py"]

_OLD = '''"""Проверка слияния pcap вручную (без pipeline)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))'''

_NEW = '''"""Проверка слияния pcap вручную (без pipeline).

Это НЕ pytest-файл: здесь нет `def test_*`, а `main()` запускается
руками (`python tests/test_multi_pcap.py`). Маркер ниже — формальность
на случай, если кто-то добавит сюда `test_*`.
"""
import sys
from pathlib import Path

import pytest
pytestmark = pytest.mark.skip(reason="manual integration script, run directly")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))'''


def apply(root: Path) -> bool:
    return patch(root, FILES[0], _OLD, _NEW)


def verify(root: Path) -> None:
    assert_applied(root, FILES[0], "pytestmark = pytest.mark.skip")
