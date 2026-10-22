# tools/fix_15_core_improvements.py
from __future__ import annotations
from pathlib import Path

import fix_utils
from fix_utils import patch, FixError

FIX_ID = "15-core-improvements"
TITLE = "Ядро: роль scanner_candidate и веса рёбер в attack_graph"

REL_ENTITIES = "paradox/aggregators/entities.py"
REL_GRAPH = "paradox/analyzers/attack_graph.py"
REL_DIALOG = "paradox_gui/dialogs/attack_graph_dialog.py"

# --- 1. entities.py ---
_ENT_TAG_OLD = '''            if ftype in ("brute_force", "vulnerable_path",
                         "ftp_brute_force", "ssh_brute_force",
                         "command_injection",
                         "port_scan", "web_scanner"):
                # src = атакующий, dst = цель
                if side == "src":
                    tags.add("attacker_tag")
                else:
                    tags.add("victim_tag")
'''
_ENT_TAG_NEW = '''            if ftype in ("brute_force", "vulnerable_path",
                         "ftp_brute_force", "ssh_brute_force",
                         "command_injection"):
                # src = атакующий, dst = цель
                if side == "src":
                    tags.add("attacker_tag")
                else:
                    tags.add("victim_tag")
            elif ftype in ("port_scan", "web_scanner"):
                # Сканеры выделяем в отдельную роль: это разведка.
                if side == "src":
                    tags.add("attacker_tag")
                    tags.add("scanner_tag")
                else:
                    tags.add("victim_tag")
'''

_ENT_ROLE_OLD = '''        else:
            # external: attacker и C2 — не взаимоисключающие.
            # Внешний сервер с finding'ом = C2-кандидат.
            # Если активный attacker_tag (реально атакует) — добавляем.
            if has_attacker:
                ent.roles.append("attacker_candidate")
            if has_findings:
                ent.roles.append("c2_candidate")
'''
_ENT_ROLE_NEW = '''        else:
            # external: attacker и C2 — не взаимоисключающие.
            # Внешний сервер с finding'ом = C2-кандидат.
            # Если активный attacker_tag (реально атакует) — добавляем.
            if has_attacker:
                ent.roles.append("attacker_candidate")
            if has_findings:
                ent.roles.append("c2_candidate")

        # Сканеры (port_scan, web_scanner) — метка поверх базовой роли.
        if "scanner_tag" in tags:
            ent.roles.append("scanner_candidate")
'''

# --- 2. attack_graph.py ---
_GRAPH_EDGE_OLD = '''@dataclass
class AttackEdge:
    src: str
    dst: str
    finding_types: list[str] = field(default_factory=list)
    phase: str = "other"
    phase_order: int = 999
    severity: str = "medium"
    confidence: float = 0.5
    first_ts: float = 0.0
    last_ts: float = 0.0

    @property
    def score(self) -> float:
        return SEVERITY_WEIGHT.get(self.severity, 0.5) * self.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src, "dst": self.dst,
            "finding_types": list(self.finding_types),
            "phase": self.phase, "phase_order": self.phase_order,
            "severity": self.severity, "confidence": round(self.confidence, 3),
            "first_ts": self.first_ts, "last_ts": self.last_ts,
        }
'''
_GRAPH_EDGE_NEW = '''@dataclass
class AttackEdge:
    src: str
    dst: str
    finding_types: list[str] = field(default_factory=list)
    phase: str = "other"
    phase_order: int = 999
    severity: str = "medium"
    confidence: float = 0.5
    first_ts: float = 0.0
    last_ts: float = 0.0
    weight: float = 1.0

    @property
    def score(self) -> float:
        return SEVERITY_WEIGHT.get(self.severity, 0.5) * self.confidence * self.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src, "dst": self.dst,
            "finding_types": list(self.finding_types),
            "phase": self.phase, "phase_order": self.phase_order,
            "severity": self.severity, "confidence": round(self.confidence, 3),
            "first_ts": self.first_ts, "last_ts": self.last_ts,
            "weight": round(self.weight, 2),
        }
'''

_GRAPH_BUILD_OLD = '''        edges.append(AttackEdge(
            src=src, dst=dst,
            finding_types=sorted(b["types"]),
            phase=b["phase"], phase_order=b["phase_order"],
            severity=b["severity"], confidence=b["confidence"],
            first_ts=b["first_ts"] or 0.0, last_ts=b["last_ts"] or 0.0,
        ))'''
_GRAPH_BUILD_NEW = '''        weight = 1.0 + 0.2 * (len(b["types"]) - 1)
        edges.append(AttackEdge(
            src=src, dst=dst,
            finding_types=sorted(b["types"]),
            phase=b["phase"], phase_order=b["phase_order"],
            severity=b["severity"], confidence=b["confidence"],
            first_ts=b["first_ts"] or 0.0, last_ts=b["last_ts"] or 0.0,
            weight=weight,
        ))'''

# --- 3. attack_graph_dialog.py ---
_DIALOG_WIDTH_OLD = '''        if sev in ("critical", "high"):
            width = 3.0
        elif sev == "medium":
            width = 2.0
        else:
            width = 1.5
        style = Qt.PenStyle.SolidLine if conf >= 0.5 else Qt.PenStyle.DashLine'''
_DIALOG_WIDTH_NEW = '''        if sev in ("critical", "high"):
            width = 3.0
        elif sev == "medium":
            width = 2.0
        else:
            width = 1.5
        # Визуальный вес: ребро с несколькими типами находок рисуется толще.
        edge_weight = float(e.get("weight", 1.0))
        width *= min(2.0, edge_weight)
        style = Qt.PenStyle.SolidLine if conf >= 0.5 else Qt.PenStyle.DashLine'''


def _try_patch(root: Path, rel: str, old: str, new: str) -> bool:
    if patch(root, rel, old, new, required=False):
        return True
    text = (root / rel).read_text(encoding="utf-8")
    if new.strip() in text:
        return False  # уже применено
    if fix_utils.DRY_RUN:
        return False
    raise FixError(f"{rel}: паттерн не найден, патч не применился")


def apply(root: Path) -> bool:
    changed = False
    for rel, pairs in [
        (REL_ENTITIES, [(_ENT_TAG_OLD, _ENT_TAG_NEW), (_ENT_ROLE_OLD, _ENT_ROLE_NEW)]),
        (REL_GRAPH,    [(_GRAPH_EDGE_OLD, _GRAPH_EDGE_NEW), (_GRAPH_BUILD_OLD, _GRAPH_BUILD_NEW)]),
        (REL_DIALOG,   [(_DIALOG_WIDTH_OLD, _DIALOG_WIDTH_NEW)]),
    ]:
        for old, new in pairs:
            if _try_patch(root, rel, old, new):
                changed = True
                print(f"  [ok] {rel}")
            else:
                print(f"  [skip/already] {rel}")
    return changed
