# tools/fix_26_attack_graph_item_roles.py
"""Fix #26: QGraphicsPathItem.setData(0/1) — нестандартные роли.

Qt резервирует 0..255 под свои роли; 0 и 1 сейчас свободны, но
это не контракт — при обновлении Qt поведение может поменяться.
Используем Qt.ItemDataRole.UserRole + смещение.
"""
from __future__ import annotations
from pathlib import Path

from fix_utils import patch, assert_applied

FIX_ID = "26-attack-graph-item-roles"
TITLE = "attack_graph_dialog: роли 0/1 -> UserRole+0/+1"

REL = "paradox_gui/dialogs/attack_graph_dialog.py"

_OLD_SET = """        item.setData(0, e[\"src\"])       # для подсветки (v1.2.1: фикс)
        item.setData(1, e[\"dst\"])       # для подсветки (v1.2.1: фикс)"""

_NEW_SET = """        item.setData(Qt.ItemDataRole.UserRole, e[\"src\"])
        item.setData(Qt.ItemDataRole.UserRole + 1, e[\"dst\"])"""

_OLD_GET = "                key = (item.data(0), item.data(1))"
_NEW_GET = "                key = (item.data(Qt.ItemDataRole.UserRole), item.data(Qt.ItemDataRole.UserRole + 1))"


def apply(root: Path) -> bool:
    changed = False
    if patch(root, REL, _OLD_SET, _NEW_SET, required=False):
        changed = True
    if patch(root, REL, _OLD_GET, _NEW_GET, required=False):
        changed = True
    assert_applied(root, REL, "Qt.ItemDataRole.UserRole")
    return changed