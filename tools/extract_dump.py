#!/usr/bin/env python3
"""
Распаковывает source dump обратно в файлы.

Использование:
    python tools/extract_dump.py dump_backend.txt -o restored/
    python tools/extract_dump.py dump_backend.txt           # ./restored/
    python tools/extract_dump.py dump_*.txt -o restored/ --force

Существующие файлы НЕ перезаписывает без --force.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

FILE_MARKER = "# FILE: "
SEP_42 = "# " + "=" * 42
SEP_58_PREFIX = "# " + "=" * 58


def parse_dump(text: str) -> dict[str, str]:
    files: dict[str, str] = {}
    current_path: str | None = None
    current_body: list[str] = []

    def flush() -> None:
        nonlocal current_path, current_body
        if current_path is None:
            return
        # Хвостовые пустые строки — разделитель дампа, не содержимое.
        while current_body and current_body[-1] == "":
            current_body.pop()
        files[current_path] = "\n".join(current_body)
        current_path = None
        current_body = []

    for line in text.splitlines():
        if line.startswith(FILE_MARKER):
            flush()
            current_path = line[len(FILE_MARKER):].strip()
            continue
        if line.strip() == SEP_42:
            continue  # разделитель вокруг # FILE:
        if line.strip() == SEP_58_PREFIX or line.startswith("# ИТОГО:"):
            # Футер/шапка дампа. Если после них что-то есть — это уже не наши данные.
            flush()
            continue
        if current_path is not None:
            current_body.append(line)

    flush()
    return files


def _safe_target(root: Path, rel: str) -> Path | None:
    """Защита от path traversal: rel должен резолвиться внутри root."""
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        return None
    # Убираем возможный 'paradox/'/'tests/' префикс, если -o это корень.
    target = (root / rel)
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Распаковать source dump")
    ap.add_argument("dumps", nargs="+", type=Path, help="файл(ы) дампа")
    ap.add_argument(
        "-o", "--output", type=Path, default=Path("restored"),
        help="куда распаковывать (по умолчанию ./restored)",
    )
    ap.add_argument(
        "--force", action="store_true",
        help="перезаписывать существующие файлы",
    )
    args = ap.parse_args(argv)

    total_written = 0
    total_skipped = 0

    for dump in args.dumps:
        if not dump.is_file():
            print(f"error: {dump} не найден", file=sys.stderr)
            total_skipped += 1
            continue

        files = parse_dump(dump.read_text(encoding="utf-8"))
        if not files:
            print(f"error: {dump} — нет FILE-маркеров", file=sys.stderr)
            total_skipped += 1
            continue

        for rel, body in files.items():
            target = _safe_target(args.output, rel)
            if target is None:
                print(f"skip (traversal): {rel}", file=sys.stderr)
                total_skipped += 1
                continue
            if target.exists() and not args.force:
                total_skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body + "\n", encoding="utf-8")
            total_written += 1

    print(f"written: {total_written}, skipped: {total_skipped}, "
          f"output: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
