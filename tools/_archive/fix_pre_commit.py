"""Fix ruff errors in attack_graph_dialog.py (после pre-commit run)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "paradox_gui" / "dialogs" / "attack_graph_dialog.py"


REPLACEMENTS = [
    # 1. Path import (критично — без него DOT-экспорт падает)
    (
        "from PySide6.QtCore import Qt, QTimer\n",
        "from pathlib import Path\nfrom PySide6.QtCore import Qt, QTimer\n",
    ),
    # 2. F-string с вложенными двойными кавычками (Py<3.12 синтаксис)
    (
        'f"{"Внутренний" if n.get("is_internal") else "Внешний"}",',
        '("Внутренний" if n.get("is_internal") else "Внешний"),',
    ),
    # 3. E701 — if not t: return
    (
        '            if not t: return "—"\n',
        '            if not t:\n'
        '                return "—"\n',
    ),
    # 4-6. E701 — tip_parts ifs
    (
        '        if n.get("is_pivot"): tip_parts.append("<b>⚠ PIVOT</b>")\n',
        '        if n.get("is_pivot"):\n'
        '            tip_parts.append("<b>⚠ PIVOT</b>")\n',
    ),
    (
        '        if n.get("is_entry"): tip_parts.append("<b>ВХОД</b>")\n',
        '        if n.get("is_entry"):\n'
        '            tip_parts.append("<b>ВХОД</b>")\n',
    ),
    (
        '        if n.get("is_impact"): tip_parts.append("<b>ЦЕЛЬ АТАКИ</b>")\n',
        '        if n.get("is_impact"):\n'
        '            tip_parts.append("<b>ЦЕЛЬ АТАКИ</b>")\n',
    ),
    # 7-10. E701 — times.append
    (
        '            if n.get("first_ts"): times.append(n["first_ts"])\n',
        '            if n.get("first_ts"):\n'
        '                times.append(n["first_ts"])\n',
    ),
    (
        '            if n.get("last_ts"): times.append(n["last_ts"])\n',
        '            if n.get("last_ts"):\n'
        '                times.append(n["last_ts"])\n',
    ),
    (
        '            if e.get("first_ts"): times.append(e["first_ts"])\n',
        '            if e.get("first_ts"):\n'
        '                times.append(e["first_ts"])\n',
    ),
    (
        '            if e.get("last_ts"): times.append(e["last_ts"])\n',
        '            if e.get("last_ts"):\n'
        '                times.append(e["last_ts"])\n',
    ),
    # 11. E701 — label += "\n(PIVOT)"
    (
        '                if n.get("is_pivot"): label += "\\n(PIVOT)"\n',
        '                if n.get("is_pivot"):\n'
        '                    label += "\\n(PIVOT)"\n',
    ),
    # 12. B905 — zip strict
    (
        'for item, e in zip(self._edge_items, self._edges):',
        'for item, e in zip(self._edge_items, self._edges, strict=False):',
    ),
    # 13. F841 — убрать присваивание key_label
    (
        '            key_label = ET.SubElement(root, "key", id="label"',
        '            ET.SubElement(root, "key", id="label"',
    ),
    # 14. F841 — убрать присваивание key_sev
    (
        '            key_sev = ET.SubElement(root, "key", id="severity"',
        '            ET.SubElement(root, "key", id="severity"',
    ),
    # 15. F401 — защитные импорты (не используются, но нужны для проверки)
    (
        '            from paradox.analyzers.story import build_host_story\n'
        '            from paradox_gui.dialogs.host_story_dialog import HostStoryDialog\n',
        '            from paradox.analyzers.story import build_host_story  # noqa: F401\n'
        '            from paradox_gui.dialogs.host_story_dialog import HostStoryDialog  # noqa: F401\n',
    ),
]


def main():
    if not TARGET.exists():
        print(f"[ERROR] {TARGET} not found", file=sys.stderr)
        return 1

    src = TARGET.read_text(encoding="utf-8")
    applied = 0
    skipped = 0

    for old, new in REPLACEMENTS:
        if new in src:
            skipped += 1
            continue
        if old in src:
            src = src.replace(old, new, count=1)
            applied += 1
        else:
            print(f"[WARN] anchor not found: {old[:60]}...")

    TARGET.write_text(src, encoding="utf-8")
    print(f"[OK] applied={applied}, skipped={skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
