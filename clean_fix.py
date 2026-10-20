#!/usr/bin/env python3
"""
clean_fix.py — привести models.py и mitre_map.py к каноничному состоянию.

После бага идемпотентности в apply_review_fixes.py (v1/v2) в models.py
могли накопиться дубли "yara_match", а в mitre_map.py — не быть нужной
записи вовсе. Скрипт делает по факту содержимого, а не по истории запусков.

Запуск из корня проекта:
    python clean_fix.py            # применить
    python clean_fix.py --dry-run  # только показать план
"""
from __future__ import annotations

import argparse
import datetime
import py_compile
import shutil
import sys
from pathlib import Path


# =============================================================================
# models.py: оставить РОВНО ОДНУ строку "yara_match": "high",
# =============================================================================

def clean_models(path: Path, dry: bool) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"models: файл не найден ({path})"
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return False, f"models: не UTF-8 ({e})"

    lines = text.splitlines(keepends=True)
    out: list[str] = []
    seen = False
    removed = 0
    for line in lines:
        if line.strip() == '"yara_match": "high",':
            if seen:
                removed += 1
                continue
            seen = True
        out.append(line)

    if removed == 0 and seen:
        return True, "models: OK (ровно 1 копия)"
    if not seen:
        return False, "models: WARN — ни одной строки \"yara_match\": \"high\","
    if dry:
        return True, f"models: удалить {removed} лишних копий (dry-run)"

    path.write_text("".join(out), encoding="utf-8")
    return True, f"models: удалено {removed} лишних копий"


# =============================================================================
# mitre_map.py: добавить "yara_match": ("T1204",) после "command_injection"
# =============================================================================

_MITRE_ANCHOR = '    "command_injection": ("T1190", "T1059"),\n'
_MITRE_INSERT = (
    '    # yara_match: YARA-сигнатура malware в скачанном payload —\n'
    '    # обнаружение и попытка запуска (T1204).\n'
    '    "yara_match": ("T1204",),\n'
)


def fix_mitre(path: Path, dry: bool) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"mitre_map: файл не найден ({path})"
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return False, f"mitre_map: не UTF-8 ({e})"

    # Учитываем и кавычки, и возможные варианты: "yara_match" или 'yara_match'
    if '"yara_match"' in text or "'yara_match'" in text:
        return True, "mitre_map: OK (запись уже есть)"

    if _MITRE_ANCHOR not in text:
        return False, (
            "mitre_map: WARN — якорь \"command_injection\" не найден. "
            "Вставь вручную строку:   \"yara_match\": (\"T1204\",),"
        )

    if dry:
        return True, "mitre_map: добавить yara_match → T1204 (dry-run)"

    text = text.replace(_MITRE_ANCHOR, _MITRE_ANCHOR + _MITRE_INSERT, 1)
    path.write_text(text, encoding="utf-8")
    return True, "mitre_map: добавлено yara_match → T1204"


# =============================================================================
# MAIN
# =============================================================================

def find_root(start: Path) -> Path | None:
    cur = start.resolve()
    for p in (cur, *cur.parents):
        if (p / "paradox" / "config.py").is_file():
            return p
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--root", type=Path, default=None)
    args = ap.parse_args(argv)

    root = args.root or find_root(Path.cwd())
    if root is None:
        print("Не нашёл корень проекта (paradox/config.py)")
        return 2

    print(f"Корень: {root}")
    if args.dry_run:
        print("Режим: --dry-run")
    print()

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    targets = [
        ("paradox/models.py", clean_models),
        ("paradox/detectors/mitre_map.py", fix_mitre),
    ]

    ok_all = True
    for relpath, fn in targets:
        path = root / relpath
        if not path.is_file():
            print(f"  ERR   {relpath}: файл не найден")
            ok_all = False
            continue

        # Свежий бэкап с timestamp — не трогаем старые *.bak от v1/v2
        if not args.dry_run:
            bak = path.with_suffix(path.suffix + f".clean_{ts}.bak")
            shutil.copy2(path, bak)
            print(f"  bak   {bak.name}")

        ok, msg = fn(path, dry=args.dry_run)
        tag = "OK   " if ok else "ERR  "
        print(f"  {tag} {msg}")

        if not ok:
            ok_all = False
            continue

        # Проверка компиляции — только после реальной правки
        if not args.dry_run:
            try:
                py_compile.compile(str(path), doraise=True)
                print(f"        ✓ компилируется")
            except py_compile.PyCompileError as e:
                # откатываем
                bak = path.with_suffix(path.suffix + f".clean_{ts}.bak")
                if bak.exists():
                    shutil.copy2(bak, path)
                print(f"        ✗ py_compile: {e}")
                print(f"        откат из {bak.name}")
                ok_all = False
        print()

    if args.dry_run:
        print("--dry-run: ничего не записано")
    else:
        print("Готово." if ok_all else "Есть ошибки — см. выше.")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())