"""
Прогоняет все фиксы подряд, потом targeted tests, потом полный suite.

Если какой-то шаг падает — останавливается с понятным кодом выхода.

Использование:
    python tools/verify_all.py
    python tools/verify_all.py --fixes-only      # без pytest
    python tools/verify_all.py --tests-only      # без фиксов
"""
import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).parent


FIXES = [
    "fix_evidence_fallbacks",
    "fix_severity_map",
    "sync_gui_severity",
    "fix_ioc_ipv6",
    "add_regression_tests",
]

TARGETED_TESTS = [
    "tests/test_aggregators_entities.py",
    "tests/test_detectors.py",
    "tests/test_settings_view_rules.py",
    "tests/test_regressions.py",
    "tests/test_ioc_reporter.py",
    "tests/test_severity_map.py",
    "tests/test_gui_severity_sync.py",
]


def _run(cmd: list[str]) -> int:
    print(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=REPO_ROOT).returncode


def _run_fixes() -> int:
    for fix in FIXES:
        script = TOOLS_DIR / f"{fix}.py"
        if not script.exists():
            print(f"WARN: {script} not found — skip", file=sys.stderr)
            continue
        print(f"\n{'=' * 60}\n {fix}\n{'=' * 60}")
        rc = _run([sys.executable, str(script)])
        if rc != 0:
            print(
                f"FAILED: {fix} (exit {rc})", file=sys.stderr,
            )
            return rc
    return 0


def _run_tests() -> int:
    print(f"\n{'=' * 60}\n targeted tests\n{'=' * 60}")
    rc = _run([sys.executable, "-m", "pytest", "-v"] + TARGETED_TESTS)
    if rc != 0:
        print("TARGETED TESTS FAILED", file=sys.stderr)
        return rc

    print(f"\n{'=' * 60}\n full test suite\n{'=' * 60}")
    rc = _run([
        sys.executable, "-m", "pytest", "-q", "--tb=short", "tests/",
    ])
    if rc != 0:
        print("FULL SUITE FAILED", file=sys.stderr)
        return rc
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixes-only", action="store_true")
    parser.add_argument("--tests-only", action="store_true")
    args = parser.parse_args()

    if args.fixes_only and args.tests_only:
        print("--fixes-only и --tests-only взаимоисключающие", file=sys.stderr)
        return 2

    if not args.tests_only:
        rc = _run_fixes()
        if rc != 0:
            return rc

    if not args.fixes_only:
        rc = _run_tests()
        if rc != 0:
            return rc

    print("\n" + "=" * 60)
    print("✅ ALL GREEN")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
