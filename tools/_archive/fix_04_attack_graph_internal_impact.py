# tools/fix_04_attack_graph_internal_impact.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "04-attack-graph-internal-impact"
TITLE = "attack_graph: internal dst не является impact target"
REL = "paradox/analyzers/attack_graph.py"

_OLD = '''def _detect_entry_impact(edges: list[AttackEdge], config: Config) -> tuple[set[str], set[str]]:
    entries: set[str] = set()
    impacts: set[str] = set()
    for e in edges:
        dst_int = is_internal_ip(e.dst, config)
        src_int = is_internal_ip(e.src, config)
        if dst_int and not src_int and e.phase in _ENTRY_PHASES:
            entries.add(e.dst)
        if not dst_int and e.phase in _IMPACT_PHASES:
            impacts.add(e.dst)
        if dst_int and e.phase in _IMPACT_PHASES:
            impacts.add(e.dst)
    return entries, impacts
'''

_NEW = '''def _detect_entry_impact(edges: list[AttackEdge], config: Config) -> tuple[set[str], set[str]]:
    entries: set[str] = set()
    impacts: set[str] = set()
    for e in edges:
        dst_int = is_internal_ip(e.dst, config)
        src_int = is_internal_ip(e.src, config)
        if dst_int and not src_int and e.phase in _ENTRY_PHASES:
            entries.add(e.dst)
        # Impact-target — только ВНЕШНИЙ хост в фазе c2/exfil/impact.
        # Раньше сюда же добавлялся internal dst: любой внутренний
        # сервер, к которому шёл C2-трафик, объявлялся «целью атаки».
        if not dst_int and e.phase in _IMPACT_PHASES:
            impacts.add(e.dst)
    return entries, impacts
'''


def apply(root: Path) -> bool:
    changed = patch(root, REL, _OLD, _NEW, required=False)

    if not fix_utils.DRY_RUN:
        text = (root / REL).read_text(encoding="utf-8")
        if "Impact-target — только ВНЕШНИЙ" not in text:
            raise FixError(
                f"{REL}: не удалось применить — структура не совпадает с ожидаемой"
            )
    return changed
