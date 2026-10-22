# tools/fix_19_missing_imports.py
from __future__ import annotations

import re
from pathlib import Path

import fix_utils
from fix_utils import FixError

FIX_ID = "19-missing-imports"
TITLE = "Исправление импортов Path, QMessageBox и _MAX_PCAP_WARN_MB"
REL_RUN = "paradox_gui/views/run_view.py"
REL_DROP = "paradox_gui/widgets/drop_zone.py"


def _ensure_import(text: str, marker: str, insert_after_regex: str, import_line: str) -> str:
    """Добавить import_line после первого совпадения insert_after_regex, если его ещё нет."""
    if import_line in text:
        return text
    m = re.search(insert_after_regex, text, re.MULTILINE)
    if not m:
        raise FixError(f"не нашёл точку вставки: {insert_after_regex!r}")
    pos = m.end()
    return text[:pos] + "\n" + import_line + text[pos:]


def apply(root: Path) -> bool:
    changed = False

    # --- run_view.py ---
    run_path = root / REL_RUN
    run_text = run_path.read_text(encoding="utf-8")
    if "from pathlib import Path" not in run_text:
        run_text = _ensure_import(
            run_text,
            "Path",
            r"^import time\s*$",
            "from pathlib import Path",
        )
        if not fix_utils.DRY_RUN:
            run_path.write_text(run_text, encoding="utf-8", newline="\n")
        print(f"  [ok] {REL_RUN}: +from pathlib import Path")
        changed = True
    else:
        print(f"  [skip] {REL_RUN}: Path already imported")

    # --- drop_zone.py ---
    drop_path = root / REL_DROP
    drop_text = drop_path.read_text(encoding="utf-8")
    drop_changed = False

    # QMessageBox в блок импортов PySide6
    if "QMessageBox" not in drop_text:
        drop_text = _ensure_import(
            drop_text,
            "QMessageBox",
            r"^from PySide6\.QtWidgets import \(\s*\n\s*QFileDialog,\s*$",
            "    QMessageBox,",
        )
        drop_changed = True

    # _MAX_PCAP_WARN_MB после блока импортов
    if "_MAX_PCAP_WARN_MB" not in drop_text:
        # Вставим после строки `from paradox_gui.i18n import tr`
        m = re.search(r"^from paradox_gui\.i18n import tr\s*$", drop_text, re.MULTILINE)
        if m:
            pos = m.end()
            drop_text = (
                drop_text[:pos]
                + "\n\n# Порог предупреждения о размере pcap (в МБ). Ниже порога — без диалога.\n_MAX_PCAP_WARN_MB = 500"
                + drop_text[pos:]
            )
            drop_changed = True
        else:
            raise FixError(f"{REL_DROP}: не нашёл 'from paradox_gui.i18n import tr'")

    if drop_changed:
        if not fix_utils.DRY_RUN:
            drop_path.write_text(drop_text, encoding="utf-8", newline="\n")
        print(f"  [ok] {REL_DROP}: +QMessageBox, +_MAX_PCAP_WARN_MB")
        changed = True
    else:
        print(f"  [skip] {REL_DROP}: already imported")

    return changed
