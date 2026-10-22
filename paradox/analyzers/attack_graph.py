"""Attack graph reconstruction.

Строит направленный граф шагов атаки из findings + contradictions,
находит пути от entry point (initial access) до impact (C2/exfil).

Узлы = IP, вовлечённые в атаку. Рёбра = findings с src_ip/dst_ip,
сгруппированные по (src, dst). Пути = последовательности узлов от
точки входа до точки воздействия, отсортированные по силе сигнала.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from paradox.config import Config
from paradox.models import Finding
from paradox.net_utils import is_internal_ip

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}

PHASE_ORDER = {
    "recon": 10, "initial_access": 20, "execution": 30,
    "persistence": 40, "lateral_movement": 50, "c2": 60,
    "exfiltration": 70, "impact": 80, "other": 999,
}

_PHASE_OF_TYPE = {
    "port_scan": "recon", "web_scanner": "recon",
    "vulnerable_path": "initial_access", "brute_force": "initial_access",
    "ftp_brute_force": "initial_access", "ssh_brute_force": "initial_access",
    "typosquatting": "initial_access",
    "command_injection": "execution", "script_download": "execution",
    "carved_file": "execution", "yara_match": "execution",
    "beaconing": "c2", "dns_tunneling": "c2", "dga_domain": "c2",
    "cloud_tunnel": "c2", "cloud_tunnel_domain": "c2", "ja3_malware": "c2",
    "ip_check_service": "c2", "sni_without_dns": "c2",
    "sni_mismatch": "c2", "suspicious_port": "c2", "nxdomain_burst": "c2",
    "lateral_movement": "lateral_movement",
    "large_transfer": "exfiltration",
    "smtp_spam": "impact",
}

_ENTRY_PHASES = frozenset({"initial_access", "execution"})
_IMPACT_PHASES = frozenset({"c2", "exfiltration", "impact"})
_MAX_RAW_PATHS = 5000


def _phase_of(ftype: str) -> str:
    return _PHASE_OF_TYPE.get(ftype, "other")


def _merge_severity(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


@dataclass
class AttackNode:
    ip: str
    is_internal: bool
    roles: list[str] = field(default_factory=list)
    phase_reached: str = "other"
    phase_order: int = 999
    findings_count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    is_pivot: bool = False
    is_entry: bool = False
    is_impact: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip, "is_internal": self.is_internal,
            "roles": list(self.roles), "phase_reached": self.phase_reached,
            "phase_order": self.phase_order, "findings_count": self.findings_count,
            "first_ts": self.first_ts, "last_ts": self.last_ts,
            "is_pivot": self.is_pivot, "is_entry": self.is_entry,
            "is_impact": self.is_impact,
        }


@dataclass
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


@dataclass
class AttackPath:
    nodes: list[str]
    edges: list[AttackEdge]
    phases: list[str]
    severity: str
    confidence: float
    score: float
    description: str
    mitre: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes), "phases": list(self.phases),
            "severity": self.severity, "confidence": round(self.confidence, 3),
            "score": round(self.score, 3), "description": self.description,
            "mitre": list(self.mitre),
            "edges": [e.to_dict() for e in self.edges],
        }


@dataclass
class AttackGraph:
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    paths: list[AttackPath]
    entry_points: list[str]
    impact_targets: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "paths": [p.to_dict() for p in self.paths],
            "entry_points": list(self.entry_points),
            "impact_targets": list(self.impact_targets),
            "stats": {
                "nodes_total": len(self.nodes),
                "edges_total": len(self.edges),
                "paths_total": len(self.paths),
            },
        }


def _build_edges(findings: list[Finding]) -> list[AttackEdge]:
    buckets: dict[tuple[str, str], dict] = {}
    for f in findings:
        src, dst = f.src_ip, f.dst_ip
        if not src or not dst or src == dst:
            continue
        key = (src, dst)
        b = buckets.setdefault(key, {
            "types": set(), "phase": "other", "phase_order": 0,
            "severity": "info", "confidence": 0.0,
            "first_ts": None, "last_ts": None,
        })
        phase = _phase_of(f.type)
        b["types"].add(f.type)
        if phase != "other" and PHASE_ORDER[phase] > b["phase_order"]:
            b["phase"] = phase
            b["phase_order"] = PHASE_ORDER[phase]
        b["severity"] = _merge_severity(b["severity"], f.severity)
        if f.confidence > b["confidence"]:
            b["confidence"] = f.confidence
        ts = float(f.first_seen) if f.first_seen else 0.0
        if ts and (b["first_ts"] is None or ts < b["first_ts"]):
            b["first_ts"] = ts
        ts2 = float(f.last_seen) if f.last_seen else ts
        if ts2 and (b["last_ts"] is None or ts2 > b["last_ts"]):
            b["last_ts"] = ts2

    edges: list[AttackEdge] = []
    for (src, dst), b in buckets.items():
        edges.append(AttackEdge(
            src=src, dst=dst,
            finding_types=sorted(b["types"]),
            phase=b["phase"], phase_order=b["phase_order"],
            severity=b["severity"], confidence=b["confidence"],
            first_ts=b["first_ts"] or 0.0, last_ts=b["last_ts"] or 0.0,
        ))
    return edges


def _collect_pivots(contradictions: list | None) -> set[str]:
    if not contradictions:
        return set()
    out: set[str] = set()
    for c in contradictions:
        if getattr(c, "rule", None) == "victim_makes_attack":
            subj = getattr(c, "subject", None)
            if subj:
                out.add(subj)
    return out


def _detect_entry_impact(edges: list[AttackEdge], config: Config) -> tuple[set[str], set[str]]:
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


def _entity_entries_impacts(entities: Any) -> tuple[set[str], set[str]]:
    if entities is None:
        return set(), set()
    entries: set[str] = set()
    impacts: set[str] = set()
    for e in getattr(entities, "internal", []) or []:
        if "victim_candidate" in (e.roles or []):
            entries.add(e.ip)
    for e in getattr(entities, "external", []) or []:
        roles = e.roles or []
        if "c2_candidate" in roles or "attacker_candidate" in roles:
            impacts.add(e.ip)
    return entries, impacts


def _make_path(nodes: list[str], edges: list[AttackEdge], impacts: set[str]) -> AttackPath:
    phases = [e.phase for e in edges]
    sev = "info"
    for e in edges:
        sev = _merge_severity(sev, e.severity)
    conf = min((e.confidence for e in edges), default=0.5)
    base = sum(e.score for e in edges) / len(edges) if edges else 0.5
    bonus = 1.0 + 0.15 * (len(edges) - 1) if len(edges) > 1 else 1.0
    score = base * bonus
    if nodes and nodes[-1] in impacts:
        score *= 1.3
    score = min(1.0, score)

    parts: list[str] = []
    for i, node in enumerate(nodes):
        parts.append(node)
        if i < len(edges):
            parts.append(f"({','.join(edges[i].finding_types)})")
    description = " → ".join(parts)

    mitre: list[str] = []
    try:
        from paradox.detectors.mitre_map import MITRE_MAP
        for e in edges:
            for ftype in e.finding_types:
                for t in MITRE_MAP.get(ftype, ()):
                    if t not in mitre:
                        mitre.append(t)
    except ImportError:
        pass

    return AttackPath(
        nodes=list(nodes), edges=list(edges), phases=phases,
        severity=sev, confidence=conf, score=score,
        description=description, mitre=mitre,
    )


def _find_paths(edges, entries, impacts, max_depth, max_paths):
    adj: dict[str, list[AttackEdge]] = defaultdict(list)
    for e in edges:
        adj[e.src].append(e)
    for node in adj:
        adj[node].sort(key=lambda x: -x.score)

    found: list[AttackPath] = []

    def _dfs(node: str, nodes: list[str], path_edges: list[AttackEdge]):
        if len(found) >= _MAX_RAW_PATHS:
            return
        if len(path_edges) >= max_depth:
            return
        if node in impacts and path_edges:
            found.append(_make_path(nodes, path_edges, impacts))
        for e in adj.get(node, [])[:10]:
            if e.dst in nodes:
                continue
            nodes.append(e.dst)
            path_edges.append(e)
            _dfs(e.dst, nodes, path_edges)
            path_edges.pop()
            nodes.pop()

    for entry in entries:
        _dfs(entry, [entry], [])

    seen: set[tuple[str, ...]] = set()
    unique: list[AttackPath] = []
    for p in found:
        key = tuple(p.nodes)
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)

    unique.sort(key=lambda p: -p.score)
    return unique[:max_paths]


def _build_nodes(edges, entries, impacts, pivots, entities, config):
    info: dict[str, dict] = defaultdict(lambda: {
        "phase": "other", "phase_order": 0, "count": 0,
        "first_ts": None, "last_ts": None,
    })
    for e in edges:
        for ip in (e.src, e.dst):
            n = info[ip]
            if e.phase != "other" and PHASE_ORDER[e.phase] > n["phase_order"]:
                n["phase"] = e.phase
                n["phase_order"] = PHASE_ORDER[e.phase]
            n["count"] += 1
            if e.first_ts and (n["first_ts"] is None or e.first_ts < n["first_ts"]):
                n["first_ts"] = e.first_ts
            if e.last_ts and (n["last_ts"] is None or e.last_ts > n["last_ts"]):
                n["last_ts"] = e.last_ts

    roles_by_ip: dict[str, list[str]] = {}
    if entities is not None:
        for bucket in (
            getattr(entities, "internal", []) or [],
            getattr(entities, "external", []) or [],
        ):
            for e in bucket:
                roles_by_ip[e.ip] = list(e.roles or [])

    nodes: list[AttackNode] = []
    for ip, n in info.items():
        nodes.append(AttackNode(
            ip=ip, is_internal=is_internal_ip(ip, config),
            roles=roles_by_ip.get(ip, []),
            phase_reached=n["phase"], phase_order=n["phase_order"],
            findings_count=n["count"],
            first_ts=n["first_ts"] or 0.0, last_ts=n["last_ts"] or 0.0,
            is_pivot=ip in pivots,
            is_entry=ip in entries, is_impact=ip in impacts,
        ))
    nodes.sort(key=lambda n: (-n.phase_order, -n.findings_count, n.ip))
    return nodes


def build_attack_graph(
    findings: list[Finding],
    config: Config,
    entities: Any = None,
    contradictions: list | None = None,
    max_paths: int = 10,
    max_depth: int = 6,
) -> AttackGraph:
    edges = _build_edges(findings)
    pivots = _collect_pivots(contradictions)

    entries_e, impacts_e = _entity_entries_impacts(entities)
    entries_f, impacts_f = _detect_entry_impact(edges, config)
    entries = entries_e or entries_f
    impacts = impacts_e or impacts_f

    if not entries:
        for e in edges:
            if is_internal_ip(e.dst, config) and e.phase_order >= PHASE_ORDER["initial_access"]:
                entries.add(e.dst)
                break

    paths = _find_paths(edges, entries, impacts, max_depth, max_paths)
    nodes = _build_nodes(edges, entries, impacts, pivots, entities, config)

    return AttackGraph(
        nodes=nodes, edges=edges, paths=paths,
        entry_points=sorted(entries), impact_targets=sorted(impacts),
    )
