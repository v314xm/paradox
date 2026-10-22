"""Attack Graph: тесты."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


TESTS_PY = r'''"""Тесты attack_graph — построение графа атаки, поиск путей."""
import json

from paradox.analyzers.attack_graph import build_attack_graph
from paradox.config import Config
from paradox.models import Finding


def _f(ftype, src, dst, conf=0.85, sev="high", ts=100.0):
    return Finding(
        type=ftype, value=f"{src} -> {dst}",
        confidence=conf, severity=sev,
        src_ip=src, dst_ip=dst,
        first_seen=ts, last_seen=ts + 1,
    )


def test_empty_findings():
    g = build_attack_graph([], Config())
    assert g.nodes == []
    assert g.edges == []
    assert g.paths == []
    assert g.entry_points == []
    assert g.impact_targets == []


def test_single_finding_creates_edge():
    g = build_attack_graph([_f("brute_force", "10.0.0.5", "192.168.1.10")], Config())
    assert len(g.edges) == 1
    assert g.edges[0].src == "10.0.0.5"
    assert g.edges[0].dst == "192.168.1.10"
    assert g.edges[0].phase == "initial_access"


def test_finding_without_ips_skipped():
    f = Finding(type="dga_domain", value="bad.com", confidence=0.7, severity="medium")
    g = build_attack_graph([f], Config())
    assert g.edges == []


def test_self_loop_skipped():
    g = build_attack_graph([_f("brute_force", "10.0.0.5", "10.0.0.5")], Config())
    assert g.edges == []


def test_multiple_findings_on_same_edge_merged():
    findings = [
        _f("port_scan", "10.0.0.5", "192.168.1.10", sev="medium", conf=0.7),
        _f("brute_force", "10.0.0.5", "192.168.1.10", sev="high", conf=0.9),
    ]
    g = build_attack_graph(findings, Config())
    assert len(g.edges) == 1
    e = g.edges[0]
    assert set(e.finding_types) == {"port_scan", "brute_force"}
    assert e.severity == "high"
    assert e.confidence == 0.9
    assert e.phase == "initial_access"


def test_entry_point_detected():
    g = build_attack_graph([_f("brute_force", "203.0.113.5", "192.168.1.10")], Config())
    assert "192.168.1.10" in g.entry_points


def test_impact_detected():
    g = build_attack_graph([_f("large_transfer", "192.168.1.10", "80.64.102.71")], Config())
    assert "80.64.102.71" in g.impact_targets


def test_path_entry_to_impact():
    findings = [
        _f("brute_force", "203.0.113.5", "192.168.1.10"),
        _f("lateral_movement", "192.168.1.10", "192.168.1.20"),
        _f("large_transfer", "192.168.1.20", "80.64.102.71"),
    ]
    g = build_attack_graph(findings, Config())
    assert len(g.paths) >= 1
    path = g.paths[0]
    assert path.nodes[0] == "192.168.1.10"
    assert path.nodes[-1] == "80.64.102.71"
    assert len(path.nodes) == 3


def test_cycle_not_infinite():
    findings = [
        _f("brute_force", "203.0.113.5", "192.168.1.10"),
        _f("lateral_movement", "192.168.1.10", "192.168.1.20"),
        _f("lateral_movement", "192.168.1.20", "192.168.1.10"),
        _f("large_transfer", "192.168.1.20", "80.64.102.71"),
    ]
    g = build_attack_graph(findings, Config(), max_depth=10)
    for p in g.paths:
        assert len(p.nodes) == len(set(p.nodes))


def test_max_depth_respected():
    findings = [
        _f("brute_force", "203.0.113.5", "10.0.0.1"),
        _f("lateral_movement", "10.0.0.1", "10.0.0.2"),
        _f("lateral_movement", "10.0.0.2", "10.0.0.3"),
        _f("lateral_movement", "10.0.0.3", "10.0.0.4"),
        _f("large_transfer", "10.0.0.4", "80.64.102.71"),
    ]
    g = build_attack_graph(findings, Config(), max_depth=3)
    for p in g.paths:
        assert len(p.edges) <= 3


def test_pivot_marked():
    class _P:
        rule = "victim_makes_attack"
        subject = "192.168.1.10"

    findings = [
        _f("brute_force", "203.0.113.5", "192.168.1.10"),
        _f("lateral_movement", "192.168.1.10", "192.168.1.20"),
    ]
    g = build_attack_graph(findings, Config(), contradictions=[_P()])
    pivot = next(n for n in g.nodes if n.ip == "192.168.1.10")
    assert pivot.is_pivot is True


def test_nodes_phase_reached():
    findings = [
        _f("brute_force", "203.0.113.5", "192.168.1.10"),
        _f("lateral_movement", "192.168.1.10", "192.168.1.20"),
        _f("large_transfer", "192.168.1.20", "80.64.102.71"),
    ]
    g = build_attack_graph(findings, Config())
    by_ip = {n.ip: n for n in g.nodes}
    assert by_ip["192.168.1.10"].phase_reached == "lateral_movement"
    assert by_ip["80.64.102.71"].phase_reached == "exfiltration"


def test_entity_entries_used():
    class _E:
        def __init__(self, ip, roles):
            self.ip = ip
            self.roles = roles

    class _Ents:
        internal = [_E("192.168.1.10", ["victim_candidate"])]
        external = []

    findings = [_f("brute_force", "203.0.113.5", "192.168.1.10")]
    g = build_attack_graph(findings, Config(), entities=_Ents())
    assert "192.168.1.10" in g.entry_points


def test_to_dict_serializable():
    g = build_attack_graph(
        [_f("brute_force", "203.0.113.5", "192.168.1.10")], Config(),
    )
    d = g.to_dict()
    assert "nodes" in d and "edges" in d and "paths" in d
    assert "entry_points" in d and "impact_targets" in d
    assert "stats" in d
    json.dumps(d)


def test_full_chain_has_mitre():
    findings = [
        _f("brute_force", "203.0.113.5", "192.168.1.10"),
        _f("lateral_movement", "192.168.1.10", "192.168.1.20"),
        _f("large_transfer", "192.168.1.20", "80.64.102.71"),
    ]
    g = build_attack_graph(findings, Config())
    full_path = next(p for p in g.paths if "80.64.102.71" in p.nodes)
    assert len(full_path.mitre) >= 1
    assert any(t.startswith("T") for t in full_path.mitre)
'''


def main() -> int:
    target = REPO_ROOT / "tests" / "test_attack_graph.py"
    if target.exists():
        print(f"[SKIP] {target.relative_to(REPO_ROOT)} exists")
        return 0
    target.write_text(TESTS_PY, encoding="utf-8")
    print(f"[OK] created {target.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
