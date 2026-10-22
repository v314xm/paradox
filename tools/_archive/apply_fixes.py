from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path: sys.path.insert(0, str(_TOOLS_DIR))

import fix_utils
from fix_utils import FixError


def _load_fix_modules():
    modules = []
    for path in sorted(_TOOLS_DIR.glob("fix_*.py")):
        if not re.match(r"^fix_\d{2}_", path.name): continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    return modules


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    fix_utils.DRY_RUN = args.dry_run
    root = Path(args.root).resolve()

    applied = skipped = failed = 0
    for mod in _load_fix_modules():
        try:
            changed = mod.apply(root)
        except Exception as e:
            failed += 1
            print(f"✗ {mod.FIX_ID}  {mod.TITLE}\n  {e}")
            continue
        if changed:
            applied += 1
            print(f"✓ {mod.FIX_ID}  {mod.TITLE}")
        else:
            skipped += 1
            print(f"· {mod.FIX_ID}  {mod.TITLE}  (already applied)")

    print(f"\nSummary: {applied} applied, {skipped} skipped, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
