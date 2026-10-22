# tools/fix_20_drop_zone_imports.py
from __future__ import annotations
import re
from pathlib import Path

import fix_utils
from fix_utils import FixError

FIX_ID = "20-drop-zone-imports"
TITLE = "Точная вставка QMessageBox и _MAX_PCAP_WARN_MB в drop_zone.py"
REL_DROP = "paradox_gui/widgets/drop_zone.py"
REL_RUN = "paradox_gui/views/run_view.py"

_QT_IMPORT_RE = re.compile(
    r"from PySide6\.QtWidgets import \(\s*([^)]+?)\s*\)",
    re.DOTALL,
)
_MAX_CONST_RE = re.compile(r"^_MAX_PCAP_WARN_MB\s*=", re.MULTILINE)
_TR_IMPORT_RE = re.compile(r"^from paradox_gui\.i18n import tr\s*$", re.MULTILINE)


def _fix_drop_zone(root: Path) -> bool:
    path = root / REL_DROP
    if not path.exists():
        raise FixError(f"{REL_DROP}: file not found")
    text = path.read_text(encoding="utf-8")
    original = text

    # 1. Пересобрать блок from PySide6.QtWidgets import (...) с QMessageBox
    m = _QT_IMPORT_RE.search(text)
    if m is None:
        raise FixError(f"{REL_DROP}: не нашёл блок 'from PySide6.QtWidgets import (...)'")
    raw_names = m.group(1)
    names = [
        line.strip().rstrip(",").strip()
        for line in raw_names.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if "QMessageBox" not in names:
        names.append("QMessageBox")
    # Стабильный порядок, без дублей
    names = sorted(set(names))
    new_block = (
        "from PySide6.QtWidgets import (\n"
        + "".join(f"    {n},\n" for n in names)
        + ")"
    )
    text = text[: m.start()] + new_block + text[m.end():]

    # 2. Добавить _MAX_PCAP_WARN_MB после 'from paradox_gui.i18n import tr', если его нет
    if not _MAX_CONST_RE.search(text):
        tm = _TR_IMPORT_RE.search(text)
        if tm is None:
            raise FixError(f"{REL_DROP}: не нашёл 'from paradox_gui.i18n import tr'")
        pos = tm.end()
        text = (
            text[:pos]
            + "\n\n# Порог предупреждения о размере pcap (в МБ). Ниже порога — без диалога.\n"
            + "_MAX_PCAP_WARN_MB = 500"
            + text[pos:]
        )

    if text == original:
        print(f"  [skip] {REL_DROP}: уже в нужном виде")
        return False

    if not fix_utils.DRY_RUN:
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"  [ok] {REL_DROP}: QMessageBox + _MAX_PCAP_WARN_MB")
    return True


def _fix_run_view(root: Path) -> bool:
    path = root / REL_RUN
    if not path.exists():
        raise FixError(f"{REL_RUN}: file not found")
    text = path.read_text(encoding="utf-8")
    if re.search(r"^from pathlib import Path\s*$", text, re.MULTILINE):
        print(f"  [skip] {REL_RUN}: Path уже импортирован")
        return False

    m = re.search(r"^import time\s*$", text, re.MULTILINE)
    if m is None:
        raise FixError(f"{REL_RUN}: не нашёл 'import time'")
    pos = m.end()
    text = text[:pos] + "\nfrom pathlib import Path" + text[pos:]

    if not fix_utils.DRY_RUN:
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"  [ok] {REL_RUN}: +from pathlib import Path")
    return True


def apply(root: Path) -> bool:
    changed = False
    if _fix_drop_zone(root):
        changed = True
    if _fix_run_view(root):
        changed = True

    if not fix_utils.DRY_RUN:
        drop_text = (root / REL_DROP).read_text(encoding="utf-8")
        if "QMessageBox" not in drop_text:
            raise FixError(f"{REL_DROP}: QMessageBox не появился")
        if not _MAX_CONST_RE.search(drop_text):
            raise FixError(f"{REL_DROP}: _MAX_PCAP_WARN_MB не появился")

        run_text = (root / REL_RUN).read_text(encoding="utf-8")
        if "from pathlib import Path" not in run_text:
            raise FixError(f"{REL_RUN}: Path не появился")
    return changed
