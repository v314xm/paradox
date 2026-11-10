"""
Проверка проекта перед коммитом/релизом: ruff + полный pytest.

Почему не «pytest && echo green»: на Windows полный прогон завершается
кодом 0xC0000005 (падение интерпретатора на выходе, не тесты) и не
печатает итоговую строку. Поэтому результат берётся из --junitxml,
а код возврата pytest используется только как подсказка.

Использование:
    python tools/verify_all.py              # ruff + полный прогон
    python tools/verify_all.py --skip-lint  # только тесты
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
JUNIT_PATH = REPO_ROOT / ".qwen" / "tmp" / "junit_verify_all.xml"

RUFF_TARGETS = ["paradox", "tests", "paradox_gui", "tools"]

# Коды, которыми Windows убивает pytest уже после прогона.
_WINDOWS_TEARDOWN_CODES = {0xC0000005, 0xC0000409, -1073741819, -1073740791}


def _run(cmd: list[str]) -> int:
    print(f"\n$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=REPO_ROOT).returncode


def _junit_totals(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suite = root.find("testsuite") if root.tag == "testsuites" else root
    if suite is None:
        raise RuntimeError(f"{path}: нет <testsuite>")
    return {
        key: int(suite.get(key, 0))
        for key in ("tests", "failures", "errors", "skipped")
    }


def _run_lint() -> int:
    print(f"\n{'=' * 60}\n ruff\n{'=' * 60}")
    rc = _run([sys.executable, "-m", "ruff", "check", *RUFF_TARGETS])
    if rc != 0:
        print("RUFF FAILED", file=sys.stderr)
    return rc


def _run_tests() -> int:
    print(f"\n{'=' * 60}\n full test suite\n{'=' * 60}")
    JUNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    JUNIT_PATH.unlink(missing_ok=True)

    rc = _run([
        sys.executable, "-m", "pytest", "-q",
        "--junitxml", str(JUNIT_PATH), "tests",
    ])

    if not JUNIT_PATH.exists():
        print(
            "FAILED: pytest не оставил junit-отчёт — прогон не состоялся",
            file=sys.stderr,
        )
        return 1

    totals = _junit_totals(JUNIT_PATH)
    print(
        f"\ntests={totals['tests']} failures={totals['failures']} "
        f"errors={totals['errors']} skipped={totals['skipped']}"
    )

    if totals["failures"] or totals["errors"]:
        print(
            f"TESTS FAILED: {totals['failures']} failures, "
            f"{totals['errors']} errors",
            file=sys.stderr,
        )
        return 1

    if rc != 0 and rc not in _WINDOWS_TEARDOWN_CODES:
        print(
            f"WARN: pytest exit {rc}, но junit чистый — проверь вручную",
            file=sys.stderr,
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--skip-lint", action="store_true", help="не запускать ruff",
    )
    args = parser.parse_args()

    if not args.skip_lint and _run_lint() != 0:
        return 1
    if _run_tests() != 0:
        return 1

    print("\n" + "=" * 60)
    print("OK: ruff чист, тесты зелёные")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
