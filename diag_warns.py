#!/usr/bin/env python3
"""
diag_warns.py v1.1 — пишет результат сам в diag_output.txt (UTF-8),
без перенаправления PowerShell. Плюс печатает в консоль.

Запуск:
    python diag_warns.py
"""
from __future__ import annotations
import io
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path


CHECKS = [
    ("dga: allowlist", "paradox/detectors/dga.py",
     [r"def\s+_is_allowlisted", r"endswith.*allowlist"]),

    ("toggle api keys", "paradox_gui/views/settings_view.py",
     [r"def\s+_toggle_api_keys_visibility"]),

    ("reverse_asymmetry config",
     "paradox/contradictions/rules/e_reverse_asymmetry.py",
     [r"def\s+find_contradictions"]),

    ("port_service_mismatch config",
     "paradox/contradictions/rules/f_port_service_mismatch.py",
     [r"def\s+find_contradictions"]),

    ("urlscan 404", "paradox/integrations/urlscan.py",
     [r"def\s+_fetch"]),

    ("mitre yara_match", "paradox/detectors/mitre_map.py",
     [r"MITRE_MAP", r'"command_injection"', r'"yara']),

    ("empty_states 17", "paradox_gui/widgets/empty_states.py",
     [r"def\s+findings_empty_label", r"\b17\b"]),

    ("gui version", "paradox_gui/__init__.py",
     [r"__version__"]),
]


def dump_context(path: Path, pattern: str, radius: int = 25) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        print(f"  !!! НЕ UTF-8: {e}")
        print(f"  первые 200 байт: {path.read_bytes()[:200]!r}")
        return
    except FileNotFoundError:
        print(f"  !!! файл не найден")
        return

    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(pattern, line):
            start = max(0, i - radius)
            end = min(len(lines), i + radius + 1)
            print(f"  -- совпадение в строке {i+1} по /{pattern}/ --")
            for j in range(start, end):
                marker = ">" if j == i else " "
                print(f"  {marker}{j+1:4d}| {lines[j]}")
            print()
            return
    print(f"  xxx паттерн /{pattern}/ не найден")


def run_all() -> None:
    root = Path.cwd()
    for p in (root, *root.parents):
        if (p / "paradox" / "config.py").is_file():
            root = p
            break

    print(f"Корень: {root}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"CWD:    {Path.cwd()}")
    print()

    for label, relpath, patterns in CHECKS:
        path = root / relpath
        print("=" * 72)
        print(f">> {label}")
        print(f"   {relpath}")
        print(f"   существует: {path.exists()}")
        if path.exists():
            try:
                print(f"   размер: {path.stat().st_size} байт")
            except OSError as e:
                print(f"   размер: ОШИБКА {e}")
        print("=" * 72)
        for pat in patterns:
            dump_context(path, pat)
        print()


def main() -> int:
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_all()
    text = buf.getvalue()

    # 1) гарантированно UTF-8 (PowerShell не участвует)
    out_file = Path("diag_output.txt")
    out_file.write_text(text, encoding="utf-8")

    # 2) дублируем в консоль, чтобы видеть сразу
    try:
        print(text)
    except UnicodeEncodeError:
        # cp1251-консоль с редкими символами — не падаем, файл уже есть
        sys.stdout.write(text.encode("ascii", "replace").decode("ascii"))

    print(f"\n[OK] записано: {out_file.resolve()} ({len(text)} символов)")
    return 0


if __name__ == "__main__":
    sys.exit(main())