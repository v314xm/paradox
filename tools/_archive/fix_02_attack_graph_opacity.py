# tools/fix_02_attack_graph_opacity.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "02-attack-graph-opacity"
TITLE = "Attack graph: объединить time- и path-фильтры видимости"
REL = "paradox_gui/dialogs/attack_graph_dialog.py"

_INIT_OLD = '''        self._t_min = 0.0
        self._t_max = 0.0
        self._play_timer = QTimer(self)
'''

_INIT_NEW = '''        self._t_min = 0.0
        self._t_max = 0.0
        # State for combined visibility (see _apply_visibility).
        self._current_cutoff: float = float("inf")
        self._selected_nodes: set[str] | None = None
        self._selected_edges: set[tuple[str, str]] | None = None
        self._play_timer = QTimer(self)
'''

_TIME_OLD = '''    def _on_time_changed(self, val: int):
        """Плавно скрываем то, что ещё не произошло."""
        if self._t_max <= self._t_min:
            return

        frac = val / 1000.0
        current_t = self._t_min + (self._t_max - self._t_min) * frac
        self._update_time_label(current_t)

        for n in self._nodes:
            item = self._node_items.get(n["ip"])
            if not item:
                continue
            # Узел виден, если его время наступило (или у него нет таймстампа)
            visible = (not n.get("first_ts")) or (n["first_ts"] <= current_t + 1.0)
            item.setOpacity(1.0 if visible else 0.05)

        for item, e in zip(self._edge_items, self._edges, strict=False):
            visible = (not e.get("first_ts")) or (e["first_ts"] <= current_t + 1.0)
            item.setOpacity(1.0 if visible else 0.05)
'''

_TIME_NEW = '''    def _on_time_changed(self, val: int):
        """Установить момент времени — делегировать в _apply_visibility."""
        if self._t_max <= self._t_min:
            return

        frac = val / 1000.0
        current_t = self._t_min + (self._t_max - self._t_min) * frac
        self._current_cutoff = current_t
        self._update_time_label(current_t)
        self._apply_visibility()

    def _apply_visibility(self) -> None:
        """Единая точка применения видимости."""
        cutoff = self._current_cutoff
        path_nodes = self._selected_nodes
        path_edges = self._selected_edges

        for n in self._nodes:
            item = self._node_items.get(n["ip"])
            if not item:
                continue
            in_time = (not n.get("first_ts")) or (n["first_ts"] <= cutoff + 1.0)
            if not in_time:
                item.setOpacity(0.05)
            elif path_nodes is not None:
                item.setOpacity(1.0 if n["ip"] in path_nodes else 0.15)
            else:
                item.setOpacity(1.0)

        for item, e in zip(self._edge_items, self._edges, strict=False):
            in_time = (not e.get("first_ts")) or (e["first_ts"] <= cutoff + 1.0)
            if not in_time:
                item.setOpacity(0.05)
            elif path_edges is not None:
                key = (item.data(0), item.data(1))
                item.setOpacity(1.0 if key in path_edges else 0.25)
            else:
                item.setOpacity(1.0)
'''

_SEL_OLD = '''    def _on_select(self, row: int):
        if row < 0 or row >= len(self._paths):
            return
        path = self._paths[row]
        nodes_in = set(path.get("nodes", []))
        edges_in = {(e["src"], e["dst"]) for e in path.get("edges", [])}

        for ip, item in self._node_items.items():
            item.setOpacity(1.0 if ip in nodes_in else 0.15)
        for item in self._edge_items:
            _src, _dst = item.data(0), item.data(1)
            if (_src, _dst) in edges_in:
                item.setOpacity(1.0)
            else:
                item.setOpacity(0.25)

        html = f"<h3>Путь {row + 1}</h3>"
'''

_SEL_NEW = '''    def _on_select(self, row: int):
        if row < 0 or row >= len(self._paths):
            return
        path = self._paths[row]
        self._selected_nodes = set(path.get("nodes", []))
        self._selected_edges = {
            (e["src"], e["dst"]) for e in path.get("edges", [])
        }
        self._apply_visibility()

        html = f"<h3>Путь {row + 1}</h3>"
'''


def apply(root: Path) -> bool:
    changed = False
    for old, new in (
        (_INIT_OLD, _INIT_NEW),
        (_TIME_OLD, _TIME_NEW),
        (_SEL_OLD,  _SEL_NEW),
    ):
        if patch(root, REL, old, new, required=False):
            changed = True

    if not fix_utils.DRY_RUN:
        text = (root / REL).read_text(encoding="utf-8")
        if "_apply_visibility" not in text:
            raise FixError(
                f"{REL}: не удалось применить — структура не совпадает с ожидаемой"
            )
    return changed
