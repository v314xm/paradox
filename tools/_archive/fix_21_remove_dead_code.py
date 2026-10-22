from pathlib import Path

from fix_utils import patch

FIX_ID = "fix_21"
TITLE = "Remove dead tls_parse.py and unused imports"


def apply(root: Path) -> bool:
    # 1. Удаляем файл
    changed = False
    path = root / "paradox/tls_parse.py"
    if path.exists():
        path.unlink()
        changed = True

    # 2. Убираем мусор из конфига (если остался)
    return changed
