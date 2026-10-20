#!/usr/bin/env python3
"""
apply_review_fixes_v2.py — финальный набор правок Paradox.

Запуск из корня проекта:
    python apply_review_fixes_v2.py            # применить
    python apply_review_fixes_v2.py --dry-run  # показать план

Заменяет v1. Правки, которые уже применены ранее (dga, toggle, reverse_asym,
port_service, urlscan, empty_states, version, quick_check, settings_init,
settings_elif, otx, timeline, findings_table) — НЕ включены: они в коде есть.

Что здесь:
  1. settings_view: убрать первый неполный дубль _load/_apply_performance.
  2. models: yara_match → severity high.
  3. detector_help: пробелы в ssh_brute_force.
  4. detector_help: пробелы в smtp_spam.
  5. mitre_map: yara_match → T1204 (якорь — command_injection).
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


FIXES: list[tuple[str, str, str, str]] = [

    # -------------------------------------------------------------------------
    # 1. settings_view.py: убрать первый неполный дубль _load/_apply_performance
    #    (второй, полный с QSpinBox, остаётся ниже)
    # -------------------------------------------------------------------------
    (
        "paradox_gui/views/settings_view.py",
        "settings: убрать дубль _load/_apply_performance",
        (
            "    def _load_performance(self) -> None:\n"
            "        try:\n"
            "            from paradox.config import Config\n"
            "            cfg = Config()\n"
            "            for key, widget in self._perf_inputs.items():\n"
            "                val = getattr(cfg, key, None)\n"
            "                if val is not None and isinstance(widget, QCheckBox):\n"
            "                    widget.setChecked(bool(val))\n"
            "        except ImportError:\n"
            "            pass\n"
            "\n"
            "    def _apply_performance(self) -> None:\n"
            "        values = {}\n"
            "        for key, widget in self._perf_inputs.items():\n"
            "            if isinstance(widget, QCheckBox):\n"
            "                values[key] = widget.isChecked()\n"
            "        self.config_applied.emit(values)\n"
            "\n"
            "\n"
            "    def _add_bool_row(self, form, key, label):\n"
        ),
        (
            "    def _add_bool_row(self, form, key, label):\n"
        ),
    ),

    # -------------------------------------------------------------------------
    # 2. models.py: severity для yara_match
    # -------------------------------------------------------------------------
    (
        "paradox/models.py",
        "models: yara_match severity high",
        (
            "    \"large_transfer\": \"medium\",\n"
            "    \"carved_file\": \"medium\",\n"
        ),
        (
            "    \"large_transfer\": \"medium\",\n"
            "    \"carved_file\": \"medium\",\n"
            "    \"yara_match\": \"high\",\n"
        ),
    ),

    # -------------------------------------------------------------------------
    # 3. detector_help.py: пробел в ssh_brute_force
    # -------------------------------------------------------------------------
    (
        "paradox_gui/detector_help.py",
        "detector_help: пробел ssh_brute_force",
        (
            "    \"ssh_brute_force\":\n"
            "        \"Много SSH-сессий к одному серверу с уникальных src-портов. Подбор\"\n"
            "        \"учётных данных SSH: сервер видит серию неудачных аутентификаций с одного\"\n"
            "        \"клиента за короткое окно.\",\n"
        ),
        (
            "    \"ssh_brute_force\":\n"
            "        \"Много SSH-сессий к одному серверу с уникальных src-портов. Подбор \"\n"
            "        \"учётных данных SSH: сервер видит серию неудачных аутентификаций с одного \"\n"
            "        \"клиента за короткое окно.\",\n"
        ),
    ),

    # -------------------------------------------------------------------------
    # 4. detector_help.py: пробел в smtp_spam
    # -------------------------------------------------------------------------
    (
        "paradox_gui/detector_help.py",
        "detector_help: пробел smtp_spam",
        (
            "    \"smtp_spam\":\n"
            "        \"Один хост рассылает письма на множество адресов. Спам-бот,\"\n"
            "        \"скомпрометированный аккаунт или тест рассылки. SMTP-сессия с большим\"\n"
            "        \"числом RCPT TO на одного клиента.\",\n"
        ),
        (
            "    \"smtp_spam\":\n"
            "        \"Один хост рассылает письма на множество адресов. Спам-бот, \"\n"
            "        \"скомпрометированный аккаунт или тест рассылки. SMTP-сессия с большим \"\n"
            "        \"числом RCPT TO на одного клиента.\",\n"
        ),
    ),

    # -------------------------------------------------------------------------
    # 5. mitre_map.py: yara_match → T1204
    #    Якорь — секция Execution ("command_injection"), а не "carved_file"
    #    (в MITRE_MAP записи "carved_file" нет вообще).
    #    T1204 User Execution: Malicious File — сигнатурное обнаружение
    #    malware-файла через YARA.
    # -------------------------------------------------------------------------
    (
        "paradox/detectors/mitre_map.py",
        "mitre_map: yara_match T1204",
        (
            "    # Execution\n"
            "    # command_injection: RCE через HTTP (URI / POST body) —\n"
            "    # эксплуатирует публично доступный сервис (T1190) и вызывает\n"
            "    # интерпретатор (T1059). Обе техники уместны.\n"
            "    \"command_injection\": (\"T1190\", \"T1059\"),\n"
        ),
        (
            "    # Execution\n"
            "    # command_injection: RCE через HTTP (URI / POST body) —\n"
            "    # эксплуатирует публично доступный сервис (T1190) и вызывает\n"
            "    # интерпретатор (T1059). Обе техники уместны.\n"
            "    \"command_injection\": (\"T1190\", \"T1059\"),\n"
            "    # yara_match: YARA-сигнатура malware в скачанном payload —\n"
            "    # обнаружение и попытка запуска (T1204).\n"
            "    \"yara_match\": (\"T1204\",),\n"
        ),
    ),
]


# =============================================================================
# ДВИЖОК
# =============================================================================

BAK_SUFFIX = ".bak"
W, G, R, D, X = "\033[33m", "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def find_root(start: Path) -> Path | None:
    cur = start.resolve()
    for p in (cur, *cur.parents):
        if (p / "paradox" / "config.py").is_file():
            return p
    return None


def apply_one(root, relpath, name, old, new, dry):
    path = root / relpath
    if not path.is_file():
        return "ERR", f"{name} — файл не найден ({relpath})"
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return "ERR", f"{name} — не UTF-8 ({e}), пересохрани вручную"

    n_old = text.count(old)
    n_new = text.count(new)

    if n_new >= 1 and n_old == 0:
        return "SKIP", f"{name} — уже применено"
    if n_old == 0:
        return "WARN", f"{name} — old не найден (файл уже другой?)"
    if n_old > 1:
        return "WARN", f"{name} — old встречается {n_old} раз, нужен уникальный контекст"
    if dry:
        return "OK", f"{name} — будет применено ({relpath})"

    bak = path.with_suffix(path.suffix + BAK_SUFFIX)
    if not bak.exists():
        shutil.copy2(path, bak)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return "OK", f"{name} — применено"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    root = args.root or find_root(Path.cwd())
    if root is None:
        print(f"{R}Не нашёл корень проекта (paradox/config.py){X}")
        return 2

    print(f"{D}Корень: {root}{X}")
    if args.dry_run:
        print(f"{D}Режим: --dry-run{X}")
    print()

    buckets = {"OK": [], "SKIP": [], "WARN": [], "ERR": []}
    for relpath, name, old, new in FIXES:
        status, msg = apply_one(root, relpath, name, old, new, dry=args.dry_run)
        buckets[status].append(msg)
        color = {"OK": G, "SKIP": D, "WARN": W, "ERR": R}[status]
        print(f"  {color}[{status}]{X} {msg}")

    print()
    print(f"{D}── Итого ──{X}")
    for k, v in buckets.items():
        if v:
            print(f"  {k}: {len(v)}")

    if buckets["ERR"]:
        return 1
    if buckets["WARN"]:
        print(f"\n{W}Есть WARN — проверь вручную{X}")
    if not args.dry_run and buckets["OK"]:
        print(f"\n{G}Готово. Бэкапы: *.bak рядом с изменёнными файлами{X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())