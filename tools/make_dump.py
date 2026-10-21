#!/usr/bin/env python3
"""
Собирает source dump из директории в формате dump_*.txt.

Использование (из корня проекта):
    python tools/make_dump.py paradox
    python tools/make_dump.py paradox_gui
    python tools/make_dump.py tests
    python tools/make_dump.py paradox -o dump_custom.txt

По умолчанию берёт *.py, пропускает __pycache__, .pyc, .pytest_cache,
.git, .venv, venv, build, dist, node_modules.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SKIP_DIRS = {
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".git", ".hg", ".svn", ".venv", "venv", "env",
    "build", "dist", "node_modules", ".idea", ".vscode",
}
DEFAULT_EXTS = {".py"}

HEADER_LINE = "# " + "=" * 58
FILE_LINE = "# " + "=" * 42


def collect_files(root: Path, exts: set[str]) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix not in exts:
            continue
        out.append(p)
    out.sort(key=lambda p: p.as_posix())
    return out


def build_dump(root: Path, files: list[Path]) -> str:
    prefix_root = root.name + "/"
    parts: list[str] = []

    parts.append(HEADER_LINE)
    parts.append(f"# SOURCE DUMP: {prefix_root}")
    parts.append(f"# FILES: {len(files)}")
    parts.append(HEADER_LINE)
    parts.append("")

    parts.append("## ФАЙЛЫ В ЭТОМ ДАМПЕ")
    for p in files:
        rel = p.relative_to(root).as_posix()
        parts.append(f"#   {prefix_root}{rel}")
    parts.append("")

    total_bytes = 0
    total_lines = 0
    for p in files:
        rel = p.relative_to(root).as_posix()
        full = f"{prefix_root}{rel}"

        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = p.read_bytes().decode("utf-8", errors="replace")

        if not text.endswith("\n"):
            text += "\n"

        parts.append(FILE_LINE)
        parts.append(f"# FILE: {full}")
        parts.append(FILE_LINE)
        parts.append(text.rstrip("\n"))

        total_bytes += len(text.encode("utf-8"))
        total_lines += len(text.splitlines())

    parts.append("")
    parts.append(HEADER_LINE)
    parts.append(
        f"# ИТОГО: {len(files)} файлов, {total_lines} строк, "
        f"{total_bytes / 1024:.1f} КБ"
    )
    parts.append(HEADER_LINE)
    parts.append("")

    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Собрать source dump из директории")
    ap.add_argument("source", type=Path, help="директория с исходниками")
    ap.add_argument(
        "-o", "--output", type=Path, default=None,
        help="куда писать (по умолчанию ./dump_<dirname>.txt)",
    )
    ap.add_argument(
        "--ext", action="append", default=None,
        help="расширение (можно несколько раз, по умолчанию .py)",
    )
    args = ap.parse_args(argv)

    root = args.source
    if not root.is_dir():
        print(f"error: {root} — не директория", file=sys.stderr)
        return 2

    exts = set(args.ext or DEFAULT_EXTS)
    files = collect_files(root, exts)
    if not files:
        print(f"error: в {root} не найдено файлов {exts}", file=sys.stderr)
        return 1

    text = build_dump(root, files)

    out = args.output or Path(f"dump_{root.name}.txt")
    out.write_text(text, encoding="utf-8")
    kb = len(text.encode("utf-8")) / 1024
    print(f"{out}: {len(files)} файлов, {kb:.1f} КБ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
