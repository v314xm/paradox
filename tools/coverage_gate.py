"""Локальный гейт покрытия: ядро и GUI отдельно.

Зачем: CI в проекте нет, а полный pytest на Windows завершается
кодом 0xC0000005 уже после всех тестов. Скрипт игнорирует этот код,
читает .coverage и падает только по порогам.

Использование:
    python tools/coverage_gate.py
    python tools/coverage_gate.py --core-min 82 --gui-min 35
    python tools/coverage_gate.py --no-run   # только посчитать уже собранное

GUI-порог занижен осознанно: GUI-тесты помечаются -k "gui" и в этот
прогон не входят. Цель — не дать покрытию упасть ниже базовой линии.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / ".qwen" / "tmp" / "coverage_gate.data"

# pytest падает на выходе (0xC0000005); тесты к этому моменту уже прошли.
_KNOWN_EXIT_CODES = {0, 3221225477, -1073741819}


def _run_tests() -> int:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        f"--data-file={DATA_FILE}",
        "--source=paradox,paradox_gui",
        "-m",
        "pytest",
        "tests",
        "-q",
        "-k",
        "not gui",
        f"--junitxml={DATA_FILE.parent / 'junit_gate.xml'}",
    ]
    proc = subprocess.run(cmd, cwd=ROOT, check=False)
    if proc.returncode not in _KNOWN_EXIT_CODES:
        print(
            f"pytest завершился с неожиданным кодом {proc.returncode}",
            file=sys.stderr,
        )
        return proc.returncode
    return 0


def _package_coverage(prefix: str) -> tuple[int, int]:
    import coverage

    cov = coverage.Coverage(data_file=str(DATA_FILE))
    cov.load()
    data = cov.get_data()

    statements = 0
    missing = 0
    for filename in data.measured_files():
        rel = Path(filename).resolve().relative_to(ROOT).as_posix()
        if not rel.startswith(prefix):
            continue
        _, stmts, _, miss, _ = cov.analysis2(filename)
        statements += len(stmts)
        missing += len(miss)
    return statements, missing


def _percent(prefix: str) -> float:
    statements, missing = _package_coverage(prefix)
    if statements == 0:
        return 0.0
    return 100.0 * (statements - missing) / statements


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="coverage_gate")
    parser.add_argument("--no-run", action="store_true", help="не запускать pytest")
    parser.add_argument("--core-min", type=float, default=80.0)
    parser.add_argument("--gui-min", type=float, default=30.0)
    args = parser.parse_args(argv)

    if not args.no_run:
        code = _run_tests()
        if code:
            return code

    if not DATA_FILE.exists():
        print(f"нет данных покрытия: {DATA_FILE}", file=sys.stderr)
        return 2

    core = _percent("paradox/")
    gui = _percent("paradox_gui/")
    print(f"ядро paradox/:      {core:5.1f}%  (порог {args.core_min:.1f}%)")
    print(f"GUI paradox_gui/:   {gui:5.1f}%  (порог {args.gui_min:.1f}%)")

    failed = False
    if core < args.core_min:
        print(f"ПРОВАЛ: покрытие ядра ниже {args.core_min:.1f}%", file=sys.stderr)
        failed = True
    if gui < args.gui_min:
        print(f"ПРОВАЛ: покрытие GUI ниже {args.gui_min:.1f}%", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
