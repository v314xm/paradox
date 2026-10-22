# tools/fix_21_bump_version.py
from __future__ import annotations
import re
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "21-bump-version"
TITLE = "Bump версия до 1.3.0 (packages + CHANGELOG + optional pyproject)"

REL_CORE_INIT = "paradox/__init__.py"
REL_GUI_INIT = "paradox_gui/__init__.py"
REL_CHANGELOG = "CHANGELOG.md"

# Patch (exact-match) — для известных файлов
_OLD_CORE = '__version__ = "1.2.0"'
_NEW_CORE = '__version__ = "1.3.0"'

_OLD_GUI = '__version__ = "1.2.0"'
_NEW_GUI = '__version__ = "1.3.0"'

_OLD_CHANGELOG = "## [1.2.0] — 2026-10-22"
_NEW_CHANGELOG = "## [1.3.0] — 2026-10-22"

# Regex-based — для опциональных файлов (если есть)
_OPTIONAL_FILES = [
    ("pyproject.toml", r'(?m)^version\s*=\s*"1\.2\.0"\s*$', 'version = "1.3.0"'),
    ("setup.py", r'(?m)^\s*version\s*=\s*["\']1\.2\.0["\']', '    version="1.3.0"'),
    ("setup.cfg", r'(?m)^version\s*=\s*1\.2\.0\s*$', 'version = 1.3.0'),
]


def _bump_optional(root: Path) -> bool:
    changed = False
    for rel, pattern, replacement in _OPTIONAL_FILES:
        path = root / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        new_text = re.sub(pattern, replacement, text, count=1)
        if new_text == text:
            continue
        if fix_utils.DRY_RUN:
            print(f"  [dry-run] would bump {rel}: 1.2.0 -> 1.3.0")
        else:
            path.write_text(new_text, encoding="utf-8", newline="\n")
            print(f"  [ok] {rel}: 1.2.0 -> 1.3.0")
        changed = True
    return changed


def apply(root: Path) -> bool:
    changed = False

    if patch(root, REL_CORE_INIT, _OLD_CORE, _NEW_CORE, required=False):
        changed = True
    if patch(root, REL_GUI_INIT, _OLD_GUI, _NEW_GUI, required=False):
        changed = True
    if patch(root, REL_CHANGELOG, _OLD_CHANGELOG, _NEW_CHANGELOG, required=False):
        changed = True
    if _bump_optional(root):
        changed = True

    if not fix_utils.DRY_RUN:
        if "1.3.0" not in (root / REL_CORE_INIT).read_text(encoding="utf-8"):
            raise FixError(f"{REL_CORE_INIT}: не удалось применить")
        if "1.3.0" not in (root / REL_GUI_INIT).read_text(encoding="utf-8"):
            raise FixError(f"{REL_GUI_INIT}: не удалось применить")
        if "1.3.0" not in (root / REL_CHANGELOG).read_text(encoding="utf-8"):
            raise FixError(f"{REL_CHANGELOG}: не удалось применить")
    return changed