#!/usr/bin/env python3
"""
rename_project.py — переименование pcap-triage -> paradox.

Запуск из корня проекта (там, где лежат папки pcap_triage и pcap_triage_gui):
    python rename_project.py --dry-run  # посмотреть план
    python rename_project.py            # применить
"""
from __future__ import annotations

import argparse
import py_compile
import re
import sys
from pathlib import Path

# Порядок замен ВАЖЕН: сначала gui, потом core, чтобы не сломать подстроки.
REPLACEMENTS = [
    # Импорты и пути к модулям (Python)
    ("pcap_triage_gui", "paradox_gui"),
    ("pcap_triage", "paradox"),

    # Имена пакетов и визуальные названия
    ("pcap-triage-gui", "Paradox GUI"),
    ("pcap-triage", "Paradox"),

    # Для .exe и spec-файлов
    ("pcap-triage.spec", "paradox.spec"),

    # Названия в заголовках окон капсом
    ("PCAP-TRIAGE", "PARADOX"),
]

TEXT_EXTENSIONS = {".py", ".spec", ".md", ".toml", ".txt", ".yml", ".yaml", ".cfg", ".ini"}


def find_root(start: Path) -> Path:
    cur = start.resolve()
    for p in (cur, *cur.parents):
        if (p / "pcap_triage" / "config.py").is_file():
            return p
    return start.resolve()


def rename_dir(root: Path, old_name: str, new_name: str, dry: bool) -> None:
    old_path = root / old_name
    new_path = root / new_name
    if not old_path.exists():
        if new_path.exists():
            print(f"  SKIP  Папка {old_name} уже переименована в {new_name}")
        else:
            print(f"  WARN  Папка {old_name} не найдена")
        return

    if new_path.exists():
        print(f"  ERR   Папка {new_name} уже существует! Слияние не поддерживается.")
        return

    if dry:
        print(f"  OK    Переименовать папку: {old_name} -> {new_name}")
    else:
        old_path.rename(new_path)
        print(f"  OK    Папка переименована: {old_name} -> {new_name}")


def replace_in_files(root: Path, dry: bool) -> None:
    changed_files = 0
    total_replacements = 0

    for ext in TEXT_EXTENSIONS:
        for path in root.rglob(f"*{ext}"):
            # Пропускаем служебные папки
            if any(part in {".git", ".venv", "venv", "__pycache__", "build", "dist", ".idea"} for part in path.parts):
                continue
            # Пропускаем сам скрипт
            if path.name == "rename_project.py":
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            original_text = text
            file_replacements = 0

            for old, new in REPLACEMENTS:
                if old in text:
                    count = text.count(old)
                    text = text.replace(old, new)
                    file_replacements += count

            if text != original_text:
                changed_files += 1
                total_replacements += file_replacements
                if dry:
                    print(f"  OK    Обновить {path.relative_to(root)} ({file_replacements} замен)")
                else:
                    path.write_text(text, encoding="utf-8")
                    print(f"  OK    Обновлён {path.relative_to(root)} ({file_replacements} замен)")

    if not dry and changed_files > 0:
        print(f"\n  Итого: обновлено файлов: {changed_files}, замен: {total_replacements}")


def check_compile(root: Path) -> bool:
    errs = []
    for pkg in ("paradox", "paradox_gui"):
        pkg_dir = root / pkg
        if not pkg_dir.is_dir():
            continue
        for p in pkg_dir.rglob("*.py"):
            try:
                py_compile.compile(str(p), doraise=True)
            except py_compile.PyCompileError as e:
                errs.append(f"{p.name}: {str(e).splitlines()[0]}")

    if not errs:
        print("\n  ✓ Компиляция успешна.")
        return True
    else:
        print("\n  ✗ Ошибки компиляции:")
        for e in errs[:10]:
            print(f"    - {e}")
        return False


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    root = find_root(Path.cwd())
    if not root or not (root / "pcap_triage").exists():
        print("ОШИБКА: Запустите скрипт из корня проекта (где находится папка pcap_triage).")
        sys.exit(1)

    print(f"Корень проекта: {root}")
    if args.dry_run:
        print("Режим: --dry-run (ничего не изменяется)\n")
    else:
        print("ВНИМАНИЕ: Убедитесь, что вы сделали коммит в Git перед запуском!\n")

    # 1. Переименование папок
    print("--- Переименование папок ---")
    rename_dir(root, "pcap_triage_gui", "paradox_gui", args.dry_run)
    rename_dir(root, "pcap_triage", "paradox", args.dry_run)

    # 2. Замена в файлах
    print("\n--- Обновление текста в файлах ---")
    replace_in_files(root, args.dry_run)

    if not args.dry_run:
        print("\n--- Проверка компиляции ---")
        check_compile(root)

        print("\nГотово! Что дальше:")
        print("1. Запустите GUI: python -m paradox_gui")
        print("2. Проверьте CLI: python -m paradox --help")
        print(
            "3. Если используете PyInstaller, переименуйте pcap-triage.spec в paradox.spec (если скрипт не сделал это)")
        print("   и поменяйте в нем name='paradox'.")


if __name__ == "__main__":
    sys.exit(main())