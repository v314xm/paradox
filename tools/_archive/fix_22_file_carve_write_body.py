"""Fix #22: file_carve_write_body=true не писал тела файлов на диск.

pipeline._extract передавал output_dir=None в carve_files(),
поэтому условие `if write_body and output_dir is not None` всегда
ложно. Пользователь включал «Сохранять тела файлов на диск» в
Настройках → Производительность — файлы не появлялись.

Фикс: передаём config.output_dir / "carved". carve_files() сам
проверит write_body и папку не создаст, если выключено.
"""
from __future__ import annotations
from pathlib import Path

from fix_utils import patch, FixError, assert_applied

FIX_ID = "22-file-carve-write-body"
TITLE = "file_carve: писать тела файлов в output_dir/carved"

REL = "paradox/pipeline.py"

_OLD = """            try:
                state.carved_files = carve_files(state, config, output_dir=None)
            except Exception:
                state.extractor_errors["file_carve"] += 1"""

_NEW = """            try:
                _carved_dir = config.output_dir / "carved"
                state.carved_files = carve_files(
                    state, config, output_dir=_carved_dir,
                )
            except Exception:
                state.extractor_errors["file_carve"] += 1"""

_MARKER = '_carved_dir = config.output_dir / "carved"'


def apply(root: Path) -> bool:
    changed = patch(root, REL, _OLD, _NEW, required=False)
    assert_applied(root, REL, _MARKER)
    return changed
