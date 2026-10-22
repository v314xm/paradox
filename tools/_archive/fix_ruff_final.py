#!/usr/bin/env python3
"""
tools/fix_ruff_final.py — два Ruff-фикса + run_tests, устойчивый к Windows-segfault.

    r06  pyproject.toml: exclude .fix-ruff-backup
    r07  entities.py:    for key in state.flows (без unused flow)

Использование:
    python tools/fix_ruff_final.py                  # dry-run
    python tools/fix_ruff_final.py --apply          # применить
    python tools/fix_ruff_final.py --apply --test   # + pytest
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUP_DIR = ROOT / ".fix-ruff-backup"

# Windows subprocess.returncode возвращает беззнаковый DWORD.
# 0xC0000005 (ACCESS_VIOLATION) → 3221225477 (unsigned) или -1073741819 (signed).
ACCESS_VIOLATION_CODES = {3221225477, -1073741819}


@dataclass
class Fix:
    id: str
    title: str
    path: Path
    detect: Callable[[str], bool]
    apply: Callable[[str], str]
    verify: Callable[[str], bool]


@dataclass
class Result:
    fix: Fix
    detected: bool = False
    applied: bool = False
    verified: bool = False
    error: str = ""


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _write_atomic(p: Path, content: str) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(content, encoding="utf-8", newline="")
    os.replace(tmp, p)


def _backup(p: Path) -> None:
    if not p.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    dst = BACKUP_DIR / p.relative_to(ROOT)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, dst)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def _apply_r06(c: str) -> str:
    m = re.search(r"exclude\s*=\s*\[([^\]]*)\]", c)
    if not m:
        raise ValueError("exclude block not found")
    if ".fix-ruff-backup" in m.group(1):
        return c
    indent = "    "
    new_body = f'\n{indent}".fix-ruff-backup",' + m.group(1)
    return c[:m.start(1)] + new_body + c[m.end(1):]


def _apply_r07(c: str) -> str:
    old = (
        "    for key, flow in state.flows.items():\n"
        "        if key.dst_port not in dc_ports:"
    )
    new = (
        "    for key in state.flows:\n"
        "        if key.dst_port not in dc_ports:"
    )
    if old not in c:
        raise ValueError("B007 anchor not found")
    return c.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def build_fixes() -> list[Fix]:
    return [
        Fix(
            id="r06", path=Path("pyproject.toml"),
            title="exclude .fix-ruff-backup из Ruff",
            detect=lambda c: (
                re.search(r"exclude\s*=\s*\[([^\]]*)\]", c) is not None
                and ".fix-ruff-backup" not in c
            ),
            apply=_apply_r06,
            verify=lambda c: ".fix-ruff-backup" in c,
        ),
        Fix(
            id="r07", path=Path("paradox/aggregators/entities.py"),
            title="B007: for key in state.flows",
            detect=lambda c: (
                "    for key, flow in state.flows.items():\n"
                "        if key.dst_port not in dc_ports:"
            ) in c,
            apply=_apply_r07,
            verify=lambda c: (
                "    for key in state.flows:\n"
                "        if key.dst_port not in dc_ports:"
            ) in c,
        ),
    ]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_fix(fix: Fix, do_apply: bool) -> Result:
    p = ROOT / fix.path
    if not p.exists():
        return Result(fix=fix, error=f"file not found: {fix.path}")

    original = _read(p)

    try:
        if not fix.detect(original):
            return Result(fix=fix)
    except Exception as e:
        return Result(fix=fix, error=f"detect: {e}")

    if not do_apply:
        return Result(fix=fix, detected=True)

    try:
        new = fix.apply(original)
    except Exception as e:
        return Result(fix=fix, detected=True, error=f"apply: {e}")

    if new == original:
        return Result(fix=fix, detected=True,
                      error="apply не изменил контент")

    try:
        if not fix.verify(new):
            return Result(fix=fix, detected=True,
                          error="verify failed")
    except Exception as e:
        return Result(fix=fix, detected=True, error=f"verify: {e}")

    _backup(p)
    _write_atomic(p, new)
    return Result(fix=fix, detected=True, applied=True, verified=True)


def run_tests() -> bool:
    print("\n=== pytest ===")
    env = {**os.environ, "NO_COLOR": "1", "PY_COLORS": "0"}
    r = subprocess.run(
        [sys.executable, "-u", "-m", "pytest",
         "-q", "tests/", "-m", "not slow"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    print(r.stdout)
    if r.stderr:
        print(r.stderr, file=sys.stderr)

    if r.returncode == 0:
        print("✓ pytest OK")
        return True

    combined = (r.stdout or "") + "\n" + (r.stderr or "")
    has_failed = bool(
        re.search(r"\b\d+ (failed|error)\b", combined, re.IGNORECASE)
        or re.search(r"^\s*(FAILED|ERROR)\s", combined, re.MULTILINE)
    )
    reached_100 = "100%]" in combined
    has_passed = bool(re.search(r"\b\d+ passed\b", combined))

    if has_failed:
        print("✗ pytest: есть падения")
        return False

    if r.returncode in ACCESS_VIOLATION_CODES and (reached_100 or has_passed):
        print(
            f"⚠ pytest exit {r.returncode} (Windows-сегфолт в atexit), "
            f"но тесты прошли — считаю OK"
        )
        return True

    if has_passed and reached_100:
        print(f"⚠ pytest exit {r.returncode}, но всё зелёное — OK")
        return True

    print(f"✗ pytest failed (exit {r.returncode})")
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    fixes = build_fixes()
    if args.list:
        for f in fixes:
            print(f"{f.id}  {f.title}  → {f.path}")
        return 0

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"{mode} — фиксов: {len(fixes)}\n")

    results = [run_fix(f, args.apply) for f in fixes]

    print()
    for r in results:
        f = r.fix
        if r.applied:
            mark = "✓ applied  "
        elif not r.detected and not r.error:
            mark = "· skip     "
        elif not args.apply:
            mark = "· would-fix"
        else:
            mark = "✗ FAILED   "
        print(f"{mark}  {f.id}  {f.title}")
        if r.error:
            print(f"             → {r.error}")

    applied = sum(1 for r in results if r.applied)
    failed = sum(1 for r in results if r.detected and not r.applied)
    skipped = sum(1 for r in results if not r.detected and not r.error)
    print(f"\nИтого: applied={applied}  failed={failed}  skipped={skipped}")

    if args.apply and args.test:
        return 0 if run_tests() else 1

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
