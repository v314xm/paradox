"""Fix: attack_graph phase calculation."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH = REPO_ROOT / "paradox" / "analyzers" / "attack_graph.py"


def _patch(path, old, new, name):
    src = path.read_text(encoding="utf-8")
    if new in src and old not in src:
        print(f"[SKIP] {name}: already applied")
        return True
    if old not in src:
        print(f"[ERROR] {name}: anchor not found", file=sys.stderr)
        return False
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


def fix_build_edges():
    old = (
        '        b = buckets.setdefault(key, {\n'
        '            "types": set(), "phase": "other", "phase_order": 999,\n'
        '            "severity": "info", "confidence": 0.0,\n'
        '            "first_ts": None, "last_ts": None,\n'
        '        })\n'
        '        phase = _phase_of(f.type)\n'
        '        b["types"].add(f.type)\n'
        '        if PHASE_ORDER[phase] > b["phase_order"]:\n'
        '            b["phase"] = phase\n'
        '            b["phase_order"] = PHASE_ORDER[phase]\n'
    )
    new = (
        '        b = buckets.setdefault(key, {\n'
        '            "types": set(), "phase": "other", "phase_order": 0,\n'
        '            "severity": "info", "confidence": 0.0,\n'
        '            "first_ts": None, "last_ts": None,\n'
        '        })\n'
        '        phase = _phase_of(f.type)\n'
        '        b["types"].add(f.type)\n'
        '        if phase != "other" and PHASE_ORDER[phase] > b["phase_order"]:\n'
        '            b["phase"] = phase\n'
        '            b["phase_order"] = PHASE_ORDER[phase]\n'
    )
    return _patch(PATH, old, new, "_build_edges phase_order")


def fix_build_nodes():
    old = (
        '    info: dict[str, dict] = defaultdict(lambda: {\n'
        '        "phase": "other", "phase_order": 999, "count": 0,\n'
        '        "first_ts": None, "last_ts": None,\n'
        '    })\n'
        '    for e in edges:\n'
        '        for ip in (e.src, e.dst):\n'
        '            n = info[ip]\n'
        '            if PHASE_ORDER[e.phase] > n["phase_order"]:\n'
        '                n["phase"] = e.phase\n'
        '                n["phase_order"] = PHASE_ORDER[e.phase]\n'
    )
    new = (
        '    info: dict[str, dict] = defaultdict(lambda: {\n'
        '        "phase": "other", "phase_order": 0, "count": 0,\n'
        '        "first_ts": None, "last_ts": None,\n'
        '    })\n'
        '    for e in edges:\n'
        '        for ip in (e.src, e.dst):\n'
        '            n = info[ip]\n'
        '            if e.phase != "other" and PHASE_ORDER[e.phase] > n["phase_order"]:\n'
        '                n["phase"] = e.phase\n'
        '                n["phase_order"] = PHASE_ORDER[e.phase]\n'
    )
    return _patch(PATH, old, new, "_build_nodes phase_order")


def main():
    print("=" * 60)
    print(" fix attack_graph phase calculation")
    print("=" * 60)
    ok = True
    for fn in (fix_build_edges, fix_build_nodes):
        try:
            if not fn():
                ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
