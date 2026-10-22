"""Fix: восстановить attack_graph в run_pipeline (после git checkout)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE = REPO_ROOT / "paradox" / "pipeline.py"
RUN_VIEW = REPO_ROOT / "paradox_gui" / "views" / "run_view.py"


def _patch(path, old, new, name):
    src = path.read_text(encoding="utf-8")
    if new in src and old not in src:
        print(f"[SKIP] {name}: already applied")
        return True
    if old not in src:
        print(f"[ERROR] {name}: anchor not found in {path.name}", file=sys.stderr)
        return False
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


def patch_run_pipeline():
    src = PIPELINE.read_text(encoding="utf-8")

    run_pipeline_start = src.find("def run_pipeline(")
    if run_pipeline_start < 0:
        print("[ERROR] run_pipeline not found", file=sys.stderr)
        return False
    run_pipeline_end = src.find("\ndef run_multi_pipeline(", run_pipeline_start)
    if run_pipeline_end < 0:
        run_pipeline_end = len(src)

    run_pipeline_body = src[run_pipeline_start:run_pipeline_end]

    if "build_attack_graph" in run_pipeline_body:
        print("[SKIP] attack_graph already in run_pipeline")
        return True

    old_entities = (
        '    entities = build_entities(\n'
        '        state, findings, config, contradictions=contradictions,\n'
        '    )\n'
    )
    if old_entities not in run_pipeline_body:
        print("[ERROR] entities block not found in run_pipeline", file=sys.stderr)
        return False

    new_entities = old_entities + (
        '    # v1.2: attack graph\n'
        '    try:\n'
        '        from paradox.analyzers.attack_graph import build_attack_graph\n'
        '        _attack_graph = build_attack_graph(\n'
        '            findings=findings, config=config,\n'
        '            entities=entities, contradictions=contradictions,\n'
        '        )\n'
        '        _attack_graph_dict = _attack_graph.to_dict()\n'
        '    except Exception:\n'
        '        _attack_graph_dict = {\n'
        '            "nodes": [], "edges": [], "paths": [],\n'
        '            "entry_points": [], "impact_targets": [],\n'
        '            "stats": {"nodes_total": 0, "edges_total": 0, "paths_total": 0},\n'
        '        }\n'
    )

    old_return = (
        '        "contradictions": [c.to_dict() for c in contradictions],\n'
    )
    if old_return not in run_pipeline_body:
        print("[ERROR] return contradictions not found in run_pipeline", file=sys.stderr)
        return False

    new_return = old_return + (
        '        # v1.2: attack graph\n'
        '        "attack_graph": _attack_graph_dict,\n'
    )

    new_body = run_pipeline_body.replace(old_entities, new_entities, count=1)
    new_body = new_body.replace(old_return, new_return, count=1)

    new_src = src[:run_pipeline_start] + new_body + src[run_pipeline_end:]
    PIPELINE.write_text(new_src, encoding="utf-8")
    print("[OK] attack_graph добавлен в run_pipeline")
    return True


def patch_button_condition():
    old = (
        "        _ag = report.get('attack_graph') or {}\n"
        "        self.btn_attack_graph.setEnabled(bool(_ag.get('paths')))\n"
    )
    new = (
        "        _ag = report.get('attack_graph') or {}\n"
        "        # v1.2.1: включаем если есть ЛЮБЫЕ данные графа (не только paths).\n"
        "        _has_attack_data = bool(_ag.get('nodes') or _ag.get('paths'))\n"
        "        self.btn_attack_graph.setEnabled(_has_attack_data)\n"
    )
    if old in RUN_VIEW.read_text(encoding="utf-8"):
        return _patch(RUN_VIEW, old, new, "run_view: button on nodes|paths")
    if "_has_attack_data" in RUN_VIEW.read_text(encoding="utf-8"):
        print("[SKIP] button condition already patched")
        return True
    print("[WARN] button anchor not found — возможно, другая версия")
    return True


def main():
    print("=" * 60)
    print(" fix attack_graph in run_pipeline")
    print("=" * 60)
    ok = True
    for fn in (patch_run_pipeline, patch_button_condition):
        try:
            if not fn():
                ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False

    print("\nVerifying...")
    sys.path.insert(0, str(REPO_ROOT))
    import importlib
    try:
        import paradox.pipeline
        importlib.reload(paradox.pipeline)
        print("[OK] pipeline imports")

        import inspect
        src = inspect.getsource(paradox.pipeline.run_pipeline)
        if "attack_graph" in src:
            print("[OK] run_pipeline builds attack_graph")
        else:
            print("[ERROR] attack_graph не появился в run_pipeline", file=sys.stderr)
            ok = False
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        ok = False

    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
