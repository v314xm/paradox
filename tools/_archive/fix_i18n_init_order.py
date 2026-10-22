#!/usr/bin/env python3
"""Фикс порядка инициализации языка в MainWindow.

Проблема:
    _build_menubar() вызывается ДО set_language(), поэтому меню
    строится на дефолтном "ru", а табы и статус-бар — уже на
    сохранённом языке. Интерфейс наполовину переведён.

Решение:
    Читать SettingsStore и вызывать set_language в самом начале
    __init__, до setWindowTitle и _build_menubar. Дубль
    инициализации из _build_tabs убираем.
"""
from __future__ import annotations

import argparse
import ast
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN_WINDOW = ROOT / "paradox_gui" / "main_window.py"


_OLD_INIT_HEAD = (
    "        super().__init__()\n"
    '        self.setWindowTitle(tr("app.title", version=APP_VERSION))'
)

_NEW_INIT_HEAD = (
    "        super().__init__()\n"
    "        # Язык читаем ДО setWindowTitle/_build_menubar: они вызывают tr().\n"
    "        from paradox_gui.settings_store import SettingsStore as _SS\n"
    "        self._settings_store = _SS()\n"
    "        _saved_lang = self._settings_store.load().get(\n"
    '            "language", DEFAULT_LANGUAGE,\n'
    "        )\n"
    "        set_language(_saved_lang)\n"
    '        self.setWindowTitle(tr("app.title", version=APP_VERSION))'
)


_OLD_TABS_DUP = (
    "        from paradox_gui.settings_store import SettingsStore\n"
    "        self._settings_store = SettingsStore()\n"
    "\n"
    '        _saved_lang = self._settings_store.load().get("language", "ru")\n'
    "        set_language(_saved_lang)\n"
    "\n"
)


def _backup(path: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = path.with_name(f"{path.name}.{ts}.bak")
    shutil.copy2(path, bak)
    return bak


def _validate(source: str, path: Path) -> None:
    try:
        ast.parse(source)
    except SyntaxError as e:
        raise RuntimeError(
            f"{path.name}: синтаксис сломан на строке {e.lineno}: {e.msg}"
        )


def patch(dry_run: bool, force: bool) -> int:
    if not MAIN_WINDOW.exists():
        print(f"error: {MAIN_WINDOW} не найден", file=sys.stderr)
        return 2

    text = MAIN_WINDOW.read_text(encoding="utf-8")
    original = text

    # 1. Добавить DEFAULT_LANGUAGE в импорт i18n.
    if "DEFAULT_LANGUAGE" not in text.split("\n", 200)[0:200][0:0] or True:
        # Проверяем точечно: есть ли уже DEFAULT_LANGUAGE в i18n-импорте
        import re
        m = re.search(
            r"from paradox_gui\.i18n import ([^\n]+)",
            text,
        )
        if m and "DEFAULT_LANGUAGE" not in m.group(1):
            text = text.replace(
                m.group(0),
                f"from paradox_gui.i18n import DEFAULT_LANGUAGE, {m.group(1)}",
                1,
            )
            print("  импорт DEFAULT_LANGUAGE добавлен")

    # 2. Вставить блок инициализации языка в начало __init__.
    if "set_language(_saved_lang)" in text and (
        "Язык читаем ДО setWindowTitle" in text
    ):
        print("  __init__: блок инициализации языка уже на месте, скип")
    elif _OLD_INIT_HEAD in text:
        text = text.replace(_OLD_INIT_HEAD, _NEW_INIT_HEAD, 1)
        print("  __init__: блок инициализации языка вставлен")
    else:
        print(
            "  [warn] __init__: шапка не найдена — файл в неожиданном "
            "состоянии",
            file=sys.stderr,
        )

    # 3. Убрать дубль из _build_tabs.
    if _OLD_TABS_DUP in text:
        text = text.replace(_OLD_TABS_DUP, "", 1)
        print("  _build_tabs: дубль set_language убран")
    else:
        print("  _build_tabs: дубля нет (или уже убран), скип")

    if text == original:
        print("\nИзменений нет — всё уже пропатчено.")
        return 0

    _validate(text, MAIN_WINDOW)

    if dry_run:
        print(
            f"\n[dry] записать {MAIN_WINDOW.relative_to(ROOT)} "
            f"({len(text)} байт, было {len(original)})"
        )
        return 0

    bak = _backup(MAIN_WINDOW)
    MAIN_WINDOW.write_text(text, encoding="utf-8")
    print(
        f"\nЗаписан {MAIN_WINDOW.relative_to(ROOT)} "
        f"(бэкап: {bak.name})"
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", "-y", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    if not args.dry_run and not args.yes:
        print("Будет изменён paradox_gui/main_window.py")
        print("  • блок set_language перенесён в начало __init__")
        print("  • дубль из _build_tabs удалён")
        print("  • бэкап сохранится как main_window.py.<ts>.bak")
        if input("Продолжить? [y/N] ").strip().lower() not in ("y", "yes", "да"):
            print("Отменено.")
            return 1

    changed = patch(args.dry_run, args.force)
    if not args.dry_run and changed:
        print()
        print("Дальше:")
        print("  python -m paradox_gui    # перезапустить — меню теперь EN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
