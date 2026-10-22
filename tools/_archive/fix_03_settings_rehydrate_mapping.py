# tools/fix_03_settings_rehydrate_mapping.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "03-rehydrate-mapping"
TITLE = "settings_rehydrate: не терять Mapping-поля"
REL = "paradox_gui/settings_rehydrate.py"

_OLD = '''    if isinstance(default, Mapping):
        return default
    return raw
'''

_NEW = '''    if isinstance(default, Mapping):
        # Mapping-поля пока не редактируются из GUI, но если в settings.json
        # появятся их overrides — надо сохранить значение, а не вернуть дефолт.
        if isinstance(raw, dict):
            try:
                return type(default)(raw)
            except Exception:
                return raw
        return raw
    return raw
'''


def apply(root: Path) -> bool:
    changed = patch(root, REL, _OLD, _NEW, required=False)

    if not fix_utils.DRY_RUN:
        text = (root / REL).read_text(encoding="utf-8")
        if "Mapping-поля пока не редактируются" not in text:
            raise FixError(
                f"{REL}: не удалось применить — структура не совпадает с ожидаемой"
            )
    return changed
