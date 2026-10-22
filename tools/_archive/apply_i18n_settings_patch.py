#!/usr/bin/env python3
"""i18n-патч SettingsView (этап 1: сайдбар, заголовки, кнопки, поиск)."""
from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SV = ROOT / "paradox_gui" / "views" / "settings_view.py"
I18N_RU = ROOT / "paradox_gui" / "i18n" / "_ru.py"
I18N_EN = ROOT / "paradox_gui" / "i18n" / "_en.py"


# ---------------------------------------------------------------------------
# Ключи (ru, en)
# ---------------------------------------------------------------------------
KEYS = {
    # сайдбар
    "settings.section.general":        ("Общие",             "General"),
    "settings.section.thresholds":     ("Пороги",            "Thresholds"),
    "settings.section.detectors":      ("Детекторы",         "Detectors"),
    "settings.section.contradictions": ("Противоречия",      "Contradictions"),
    "settings.section.allowlist":      ("Allowlist",         "Allowlist"),
    "settings.section.dga":            ("DGA",               "DGA"),
    "settings.section.brute":          ("Brute force",       "Brute force"),
    "settings.section.network":        ("Сеть",              "Network"),
    "settings.section.reports":        ("Отчёты",            "Reports"),
    "settings.section.yara":           ("YARA",              "YARA"),
    "settings.section.threatintel":    ("Threat Intel",      "Threat Intel"),
    "settings.section.perf":           ("Производительность", "Performance"),

    # заголовки страниц
    "settings.general.title":          ("Общие настройки", "General settings"),
    "settings.general.subtitle":       ("Базовые параметры интерфейса.", "Basic interface parameters."),
    "settings.thresholds.title":       ("Пороги", "Thresholds"),
    "settings.thresholds.subtitle":    (
        "Пороги детекторов из Config ядра. Изменения применяются к следующему прогону. Профиль — готовый набор значений.",
        "Detector thresholds from the core Config. Changes apply to the next run. Profile — a ready-made set of values.",
    ),
    "settings.detectors.title":        ("Детекторы", "Detectors"),
    "settings.detectors.subtitle":     (
        "Снятая галочка отключает детектор в следующем прогоне. Порядок совпадает с ядром.",
        "Unchecking disables the detector on the next run. Order matches the core.",
    ),
    "settings.contradictions.title":   ("ContradictionDetector", "ContradictionDetector"),
    "settings.contradictions.subtitle": (
        "Правила проверяют согласованность между слоями данных. Отключение правила убирает его из следующего прогона.",
        "Rules check consistency across data layers. Disabling a rule removes it from the next run.",
    ),
    "settings.allowlist.title":        ("Allowlist", "Allowlist"),
    "settings.allowlist.subtitle":     (
        "Белые списки. Совпадение с элементом убирает кандидата из findings. Один элемент на строку, # — комментарий.",
        "Whitelists. A match removes a candidate from findings. One item per line, # — comment.",
    ),
    "settings.dga.title":              ("DGA", "DGA"),
    "settings.dga.subtitle":           (
        "Итоговый allowlist детектора DGA. Сюда сливаются домены cloud tunnel и IP-check сервисов из Config. Удаление элемента означает, что DGA начнёт ругаться на него.",
        "Final DGA detector allowlist. Cloud tunnel and IP-check domains from Config are merged here. Removing an item means DGA will flag it.",
    ),
    "settings.brute.title":            ("Brute force", "Brute force"),
    "settings.brute.subtitle":         (
        "Как детектор отличает подбор пароля от обычного трафика. Пороги «сколько flows» — в разделе Пороги.",
        "How the detector distinguishes password guessing from normal traffic. Flow thresholds are in the Thresholds section.",
    ),
    "settings.network.title":          ("Сеть", "Network"),
    "settings.network.subtitle":       (
        "Списки портов и префиксов. Вводите через запятую или с новой строки. Невалидные значения подсвечиваются и не сохраняются.",
        "Port and prefix lists. Enter comma- or newline-separated. Invalid values are highlighted and not saved.",
    ),
    "settings.reports.title":          ("Отчёты", "Reports"),
    "settings.reports.subtitle":       (
        "Куда ядро складывает артефакты (кэш обогащения, carved files при включённой записи). Путь создаётся при применении.",
        "Where the core stores artifacts (enrichment cache, carved files if enabled). Path is created on apply.",
    ),
    "settings.yara.title":             ("YARA", "YARA"),
    "settings.yara.subtitle":          (
        "Пользовательские YARA-правила для поиска сигнатур в payload. Если файл не выбран, используются стандартные правила из ядра.",
        "Custom YARA rules for payload signatures. If no file is selected, default core rules are used.",
    ),
    "settings.threatintel.title":      ("Threat Intel", "Threat Intel"),
    "settings.threatintel.subtitle":   (
        "Обогащение IOC из findings. Запускается отдельно (флаг --enrich). API-ключи живут до перезапуска GUI — ядро читает их из переменных окружения в момент запроса.",
        "IOC enrichment from findings. Runs separately (--enrich flag). API keys live until GUI restart — the core reads them from env at request time.",
    ),
    "settings.perf.title":             ("Производительность", "Performance"),
    "settings.perf.subtitle":          (
        "Компромисс между глубиной анализа и скоростью. Технические лимиты (память, размеры) скрыты и работают по умолчанию.",
        "Trade-off between analysis depth and speed. Technical limits (memory, sizes) are hidden and use defaults.",
    ),

    # кнопки и прочее
    "settings.search.placeholder":     ("Поиск по настройкам (Ctrl+F)…", "Search settings (Ctrl+F)…"),
    "settings.btn.reset":              ("Сбросить к default", "Reset to default"),
    "settings.btn.apply":              ("Применить", "Apply"),
    "settings.btn.enable_all":         ("Включить все", "Enable all"),
    "settings.btn.disable_all":        ("Отключить все", "Disable all"),
    "settings.profile.label":          ("Профиль:", "Profile:"),
    "settings.profile.apply":          ("Применить профиль", "Apply profile"),
    "settings.general.language":       ("Язык интерфейса:", "Interface language:"),
}


# ---------------------------------------------------------------------------
# 1) Дописать ключи в _ru.py / _en.py
# ---------------------------------------------------------------------------
def _insert_keys_into_dict(source: str, idx: int, block: str) -> str:
    """Вставить block перед последней закрывающей } в STRINGS."""
    m = re.search(r"^STRINGS\s*:\s*dict\[str,\s*str\]\s*=\s*\{\n", source, re.MULTILINE)
    if not m:
        raise RuntimeError("STRINGS dict не найден")
    # Найти закрывающую } этого словаря: с конца файла перед "}\n"
    close_idx = source.rfind("\n}\n")
    if close_idx < 0:
        raise RuntimeError("закрывающая } словаря не найдена")
    return source[:close_idx] + "\n" + block + source[close_idx:]


def patch_lang_file(path: Path, idx: int, dry: bool, force: bool) -> bool:
    if not path.exists():
        print(f"  [warn] {path.name} не найден", file=sys.stderr)
        return False
    text = path.read_text(encoding="utf-8")

    marker = 'settings.section.general'
    if marker in text and not force:
        print(f"  {path.name}: ключи settings.* уже есть, скип")
        return False

    lines = ["    # --- SettingsView (этап 1) ---"]
    for key, pair in KEYS.items():
        val = pair[idx]
        # Экранируем кавычки и переносы
        val = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lines.append(f'    "{key}": "{val}",')
    block = "\n".join(lines) + "\n"

    new_text = _insert_keys_into_dict(text, idx, block)
    try:
        ast.parse(new_text)
    except SyntaxError as e:
        print(f"  [error] {path.name}: синтаксис сломан: {e}", file=sys.stderr)
        return False

    if dry:
        print(f"  [dry] {path.name}: +{len(KEYS)} ключей")
        return True

    _backup(path)
    path.write_text(new_text, encoding="utf-8")
    print(f"  {path.name}: +{len(KEYS)} ключей")
    return True


# ---------------------------------------------------------------------------
# 2) Патч settings_view.py — точные замены
# ---------------------------------------------------------------------------
def _gen_replacements() -> list[tuple[str, str]]:
    """Список (old, new) замен в settings_view.py."""
    return [
        # Сайдбар: заменить label на tr(key)
        (
            "        for key, label in _SECTIONS:\n"
            "            item = QListWidgetItem(label)\n",
            "        for key, _label in _SECTIONS:\n"
            '            item = QListWidgetItem(tr(f"settings.section.{key}"))\n',
        ),
        # Поиск
        (
            '        self._search_line.setPlaceholderText(\n'
            '            "Поиск по настройкам (Ctrl+F)…"\n'
            '        )\n',
            '        self._search_line.setPlaceholderText(\n'
            '            tr("settings.search.placeholder")\n'
            '        )\n',
        ),
        # Кнопки Reset/Apply
        ('        rst = QPushButton("Сбросить к default")\n',
         '        rst = QPushButton(tr("settings.btn.reset"))\n'),
        ('        apt = QPushButton("Применить")\n',
         '        apt = QPushButton(tr("settings.btn.apply"))\n'),
        # Профиль
        ('        row.addWidget(QLabel("Профиль:"))\n',
         '        row.addWidget(QLabel(tr("settings.profile.label")))\n'),
        ('        apply_btn = QPushButton("Применить профиль")\n',
         '        apply_btn = QPushButton(tr("settings.profile.apply"))\n'),
        # Языковой combo
        ('        form.addRow("Язык интерфейса:", self._lang_combo)\n',
         '        form.addRow(tr("settings.general.language"), self._lang_combo)\n'),
        # Включить все / Отключить все (детекторы)
        ('        all_btn = QPushButton("Включить все")\n',
         '        all_btn = QPushButton(tr("settings.btn.enable_all"))\n'),
        ('        none_btn = QPushButton("Отключить все")\n',
         '        none_btn = QPushButton(tr("settings.btn.disable_all"))\n'),
    ]


def patch_settings_view(dry: bool, force: bool) -> bool:
    if not SV.exists():
        print(f"  [warn] {SV.name} не найден", file=sys.stderr)
        return False
    text = SV.read_text(encoding="utf-8")
    original = text

    if "settings.section.general" in text and not force:
        print("  settings_view.py: уже пропатчен, скип")
        return False

    # Сначала — сайдбар. _SECTIONS = (("key","label"), ...)
    # Оставляем _SECTIONS как есть, меняем только итерацию.

    # Замены
    applied = 0
    for old, new in _gen_replacements():
        if old in text:
            text = text.replace(old, new, 1)
            applied += 1
        else:
            print(f"  [warn] не найдено: {old.splitlines()[0][:60]}...",
                  file=sys.stderr)

    # Заголовки страниц: _make_header("Пороги", "Пороги детекторов...")
    # Заменяем первые два литеральных аргумента _make_header для
    # конкретных страниц.
    header_patterns = [
        (r'_make_header\(\s*\n?\s*"Общие настройки",\s*\n?\s*"Базовые параметры интерфейса\.?",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.general.title"),\n            tr("settings.general.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Пороги",\s*\n?\s*"Пороги детекторов[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.thresholds.title"),\n            tr("settings.thresholds.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Детекторы",\s*\n?\s*"Снятая галочка[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.detectors.title"),\n            tr("settings.detectors.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"ContradictionDetector",\s*\n?\s*"Правила проверяют[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.contradictions.title"),\n            tr("settings.contradictions.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Allowlist",\s*\n?\s*"Белые списки[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.allowlist.title"),\n            tr("settings.allowlist.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"DGA",\s*\n?\s*"Итоговый allowlist[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.dga.title"),\n            tr("settings.dga.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Brute force",\s*\n?\s*"Как детектор[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.brute.title"),\n            tr("settings.brute.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Сеть",\s*\n?\s*"Списки портов[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.network.title"),\n            tr("settings.network.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Отчёты",\s*\n?\s*"Куда ядро[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.reports.title"),\n            tr("settings.reports.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"YARA",\s*\n?\s*"Пользовательские YARA[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.yara.title"),\n            tr("settings.yara.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Threat Intel",\s*\n?\s*"Обогащение IOC[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.threatintel.title"),\n            tr("settings.threatintel.subtitle"),\n        )'),
        (r'_make_header\(\s*\n?\s*"Производительность",\s*\n?\s*"Компромисс[^"]*",\s*\n?\s*\)',
         '_make_header(\n            tr("settings.perf.title"),\n            tr("settings.perf.subtitle"),\n        )'),
    ]
    for pat, repl in header_patterns:
        text, n = re.subn(pat, repl, text, count=1, flags=re.DOTALL)
        applied += n

    if text == original:
        print("  settings_view.py: изменений нет")
        return False

    try:
        ast.parse(text)
    except SyntaxError as e:
        print(f"  [error] settings_view.py: синтаксис сломан: {e}", file=sys.stderr)
        return False

    if dry:
        print(f"  [dry] settings_view.py: {applied} замен")
        return True

    _backup(SV)
    SV.write_text(text, encoding="utf-8")
    print(f"  settings_view.py: {applied} замен")
    return True


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------
def _backup(p: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = p.with_name(f"{p.name}.{ts}.bak")
    shutil.copy2(p, bak)
    return bak


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", "-y", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    if not args.dry_run and not args.yes:
        print("Изменятся: _ru.py, _en.py (+%d ключей), settings_view.py" % len(KEYS))
        if input("Продолжить? [y/N] ").strip().lower() not in ("y", "yes", "да"):
            return 1

    print("[1/3] paradox_gui/i18n/_ru.py")
    patch_lang_file(I18N_RU, 0, args.dry_run, args.force)
    print("[2/3] paradox_gui/i18n/_en.py")
    patch_lang_file(I18N_EN, 1, args.dry_run, args.force)
    print("[3/3] paradox_gui/views/settings_view.py")
    patch_settings_view(args.dry_run, args.force)
    print()
    if args.dry_run:
        print("[dry-run] ничего не записано.")
    else:
        print("Готово. Проверь: python -m pytest tests/test_i18n.py -v")
    return 0


if __name__ == "__main__":
    sys.exit(main())
