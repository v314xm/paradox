# tools/fix_08_ui_polish.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "08-ui-polish"
TITLE = "UI: DOT escaping в графе + явный display_name в DropZone"
REL_GRAPH = "paradox_gui/dialogs/attack_graph_dialog.py"
REL_DROP = "paradox_gui/widgets/drop_zone.py"
REL_RUN = "paradox_gui/views/run_view.py"

# --- 1. Attack Graph DOT Escaping ---
_GRAPH_OLD = '''            for n in self._nodes:
                color = "#40c040" if n.get("is_entry") else ("#e04040" if n.get("is_impact") else ("#e0a040" if n.get("is_pivot") else "#5a5a6a"))
                label = n["ip"]
                if n.get("is_pivot"):
                    label += "\\n(PIVOT)"
                lines.append(f'  "{n["ip"]}" [fillcolor="{color}", label="{label}"];')
'''

_GRAPH_NEW = '''            for n in self._nodes:
                color = "#40c040" if n.get("is_entry") else ("#e04040" if n.get("is_impact") else ("#e0a040" if n.get("is_pivot") else "#5a5a6a"))
                label = n["ip"]
                if n.get("is_pivot"):
                    label += "\\n(PIVOT)"
                safe_label = label.replace('"', '\\\\"')
                safe_ip = n["ip"].replace('"', '\\\\"')
                lines.append(f'  "{safe_ip}" [fillcolor="{color}", label="{safe_label}"];')
'''

_GRAPH_EDGE_OLD = '''            for e in self._edges:
                color = _PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a")
                label = ", ".join(e.get("finding_types", []))
                lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{label}", color="{color}"];')
'''

_GRAPH_EDGE_NEW = '''            for e in self._edges:
                color = _PHASE_COLOR.get(e.get("phase", "other"), "#5a5a6a")
                label = ", ".join(e.get("finding_types", []))
                safe_label = label.replace('"', '\\\\"')
                safe_src = e["src"].replace('"', '\\\\"')
                safe_dst = e["dst"].replace('"', '\\\\"')
                lines.append(f'  "{safe_src}" -> "{safe_dst}" [label="{safe_label}", color="{color}"];')
'''

# --- 2. DropZone: explicit display_name ---
_DROP_OLD = '''    def set_compact(self, path: str) -> None:
        """Схлопнуть зону в одну строку после успешного прогона.

        Освобождает ~120px по вертикали. Drag&drop и клик остаются
        рабочими: пользователь по-прежнему может перетащить новый файл
        или кликнуть, чтобы открыть диалог.
        """
        name = Path(path).name
'''

_DROP_NEW = '''    def set_compact(self, path: str, display_name: str | None = None) -> None:
        """Схлопнуть зону в одну строку после успешного прогона.

        Освобождает ~120px по вертикали. Drag&drop и клик остаются
        рабочими: пользователь по-прежнему может перетащить новый файл
        или кликнуть, чтобы открыть диалог.

        display_name — переопределяет отображаемое имя (для multi-pcap).
        Если не задано, берётся basename из path.
        """
        name = display_name or Path(path).name
'''

# --- 3. RunView: использовать display_name для multi-pcap ---
_RUN_OLD = '''        # Компактный drop zone после успешного прогона.
        if len(self._current_paths) > 1:
            self.drop_zone.set_compact(f"[multi] {len(self._current_paths)} файлов")
        elif self._current_path:
            self.drop_zone.set_compact(self._current_path)
'''

_RUN_NEW = '''        # Компактный drop zone после успешного прогона.
        if len(self._current_paths) > 1:
            self.drop_zone.set_compact(
                "",
                display_name=f"[multi] {len(self._current_paths)} файлов",
            )
        elif self._current_path:
            self.drop_zone.set_compact(self._current_path)
'''


def apply(root: Path) -> bool:
    changed = False

    # attack_graph_dialog.py
    if patch(root, REL_GRAPH, _GRAPH_OLD, _GRAPH_NEW, required=False):
        changed = True
    if patch(root, REL_GRAPH, _GRAPH_EDGE_OLD, _GRAPH_EDGE_NEW, required=False):
        changed = True

    # drop_zone.py
    if patch(root, REL_DROP, _DROP_OLD, _DROP_NEW, required=False):
        changed = True

    # run_view.py
    if patch(root, REL_RUN, _RUN_OLD, _RUN_NEW, required=False):
        changed = True

    if not fix_utils.DRY_RUN:
        graph_text = (root / REL_GRAPH).read_text(encoding="utf-8")
        if "safe_label" not in graph_text:
            raise FixError(f"{REL_GRAPH}: не удалось применить")

        drop_text = (root / REL_DROP).read_text(encoding="utf-8")
        if "display_name: str | None = None" not in drop_text:
            raise FixError(f"{REL_DROP}: не удалось применить")

        run_text = (root / REL_RUN).read_text(encoding="utf-8")
        if "display_name=f\"[multi]" not in run_text:
            raise FixError(f"{REL_RUN}: не удалось применить")

    return changed
