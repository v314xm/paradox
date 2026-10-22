# tools/fix_14_fix_i18n_conflicts.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "14-fix-i18n-conflicts"
TITLE = "Исправление конфликтов i18n и импорта tr в графах"
REL_RU = "paradox_gui/i18n/_ru.py"
REL_EN = "paradox_gui/i18n/_en.py"
REL_GRAPH = "paradox_gui/dialogs/graph_dialog.py"
REL_CONTRA_SEC = "paradox_gui/widgets/contradictions_section.py"

# 1. _ru.py: переименовать дубликат contra.title из fix_12 в contra.section_title
_RU_OLD = '''    "contra.title": "Противоречия",'''
_RU_NEW = '''    "contra.section_title": "Противоречия",'''

# 2. _en.py: то же самое
_EN_OLD = '''    "contra.title": "Contradictions",'''
_EN_NEW = '''    "contra.section_title": "Contradictions",'''

# 3. graph_dialog.py: добавить импорт tr перед try/except
_GRAPH_IMPORT_OLD = '''# Попытка импортировать диалог истории хоста
try:
    from paradox.analyzers.story import build_host_story
    from paradox_gui.dialogs.host_story_dialog import HostStoryDialog
    HAS_STORY = True
except ImportError:
    HAS_STORY = False'''
_GRAPH_IMPORT_NEW = '''from paradox_gui.i18n import tr

# Попытка импортировать диалог истории хоста
try:
    from paradox.analyzers.story import build_host_story
    from paradox_gui.dialogs.host_story_dialog import HostStoryDialog
    HAS_STORY = True
except ImportError:
    HAS_STORY = False'''

# 4. contradictions_section.py: использовать новый ключ
_CONTRA_SEC_OLD = '''        title = QLabel(tr("contra.title"))'''
_CONTRA_SEC_NEW = '''        title = QLabel(tr("contra.section_title"))'''


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL_RU, _RU_OLD, _RU_NEW, required=False): changed = True
    if patch(root, REL_EN, _EN_OLD, _EN_NEW, required=False): changed = True
    if patch(root, REL_GRAPH, _GRAPH_IMPORT_OLD, _GRAPH_IMPORT_NEW, required=False): changed = True
    if patch(root, REL_CONTRA_SEC, _CONTRA_SEC_OLD, _CONTRA_SEC_NEW, required=False): changed = True

    if not fix_utils.DRY_RUN:
        if "contra.section_title" not in (root / REL_RU).read_text(encoding="utf-8"):
            raise FixError(f"{REL_RU}: не удалось применить")
        if "from paradox_gui.i18n import tr" not in (root / REL_GRAPH).read_text(encoding="utf-8"):
            raise FixError(f"{REL_GRAPH}: не удалось применить")
    return changed
