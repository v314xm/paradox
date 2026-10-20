#!/usr/bin/env python3
"""
dedupe_yara.py — оставить в mitre_map.py ровно один каноничный блок yara_match.

Проверяет компиляцию, при ошибке откатывает из *.dedupe_<ts>.bak.

Запуск из корня проекта:
    python dedupe_yara.py            # применить
    python dedupe_yara.py --dry-run  # показать план
"""
from __future__ import annotations

import argparse
import datetime
import py_compile
import shutil
import sys
from pathlib import Path


CANONICAL_BLOCK = (
    '    # yara_match: YARA-сигнатура malware в скачанном payload —\n'
    '    # обнаружение и попытка запуска (T1204).\n'
    '    "yara_match": ("T1204",),\n'
)

ANCHOR = '    "command_injection": ("T1190", "T1059"),\n'


def clean_mitre(path: Path, dry: bool) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"mitre_map: файл не найден ({path})"
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return False, f"mitre_map: не UTF-8 ({e})"

    # Считаем, сколько сейчас копий в файле — для отчёта
    copies = text.count('"yara_match"')
    if copies == 1 and CANONICAL_BLOCK in text:
        return True, "mitre_map: OK — ровно 1 каноничная копия"

    if dry:
        return True, f"mitre_map: сейчас {copies} копий → оставить 1 каноническую (dry-run)"

    # 1. Проходим построчно: выкидываем строку значения + опциональные
    #    комментарии перед ней (про yara_match).
    lines = text.splitlines(keepends=True)
    out = []
    removed = 0
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        # Начало блока — комментарий «# yara_match: …»
        if s.startswith("# yara_match:"):
            j = i
            while j < len(lines) and lines[j].strip().startswith("#"):
                j += 1
            if j < len(lines) and '"yara_match"' in lines[j]:
                j += 1
                removed += 1
                i = j
                continue
        # Строка значения без предшествующего комментария
        if s == '"yara_match": ("T1204",),':
            removed += 1
            i += 1
            continue
        out.append(lines[i])
        i += 1

    new_text = "".join(out)

    # 2. Вставляем один канонический блок после command_injection
    if ANCHOR not in new_text:
        return False, (
            "mitre_map: якорь \"command_injection\" не найден — "
            "вставь блок вручную после него"
        )
    new_text = new_text.replace(ANCHOR, ANCHOR + CANONICAL_BLOCK, 1)

    path.write_text(new_text, encoding="utf-8")
    return True, f"mitre_map: удалено {removed} блоков, вставлен 1 канонический"


def find_root(start: Path) -> Path | None:
    cur = start.resolve()
    for p in (cur, *cur.parents):
        if (p / "paradox" / "config.py").is_file():
            return p
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    root = args.root or find_root(Path.cwd())
    if root is None:
        print("Не нашёл корень проекта (paradox/config.py)")
        return 2

    print(f"Корень: {root}")
    if args.dry_run:
        print("Режим: --dry-run")
    print()

    path = root / "paradox/detectors/mitre_map.py"
    if not path.is_file():
        print(f"ERR: {path} не найден")
        return 1

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if not args.dry_run:
        bak = path.with_suffix(path.suffix + f".dedupe_{ts}.bak")
        shutil.copy2(path, bak)
        print(f"  bak   {bak.name}")

    ok, msg = clean_mitre(path, dry=args.dry_run)
    print(f"  {'OK   ' if ok else 'ERR  '} {msg}")

    if not ok:
        return 1

    if not args.dry_run:
        try:
            py_compile.compile(str(path), doraise=True)
            print("        ✓ компилируется")
        except py_compile.PyCompileError as e:
            bak = path.with_suffix(path.suffix + f".dedupe_{ts}.bak")
            if bak.exists():
                shutil.copy2(bak, path)
            print(f"        ✗ py_compile: {e}")
            print(f"        откат из {bak.name}")
            return 1

    if args.dry_run:
        print("\n--dry-run: ничего не записано")
    else:
        print("\nГотово.")
    return 0


if __name__ == "__main__":
    sys.exit(main())