"""Три улучшения GUI: slim-history, run-log, log-rotation.

Что делает:
  1. history_view.py — сохраняем в историю не весь report, а только
     нужные для HTML-отрисовки ключи. flows/entities не используются
     в _render_html, но весят больше всего.
  2. main_window.py  — при каждом успешном прогоне пишем одну строку
     в reports/gui-runs.log. Помогает отслеживать, на каком файле
     что-то пошло не так.
  3. _runtime_hook.py — обрезаем pcap-triage-error.log при размере
     >5 МБ, оставляя последние 2.5 МБ.

Идемпотентно: повторный запуск не сломает, у каждого файла бэкап.
"""
from pathlib import Path
import shutil
from datetime import datetime


def _backup(path: Path) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = path.with_suffix(path.suffix + f".bak_{ts}")
    shutil.copy2(path, bak)
    print(f"    бэкап: {bak.name}")


def _apply(path: Path, old: str, new: str, description: str) -> None:
    if not path.exists():
        print(f"  [FAIL] {description}: файл не найден {path}")
        return

    text = path.read_text(encoding="utf-8")

    if new.strip() and new.strip() in text and old.strip() not in text:
        print(f"  [skip] {description}: уже применён")
        return

    if old not in text:
        print(f"  [FAIL] {description}: не найден маркер")
        print(f"         искали: {old[:70]!r}")
        return

    _backup(path)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  [ok]   {description}")


# =============================================================================
# 1. Slim-history
# =============================================================================
# Report от run_pipeline содержит: summary, findings, contradictions,
# provenance, entities, flows. Последние два тяжелее всего — на 334 МБ
# pcap это десятки МБ на запись. При этом в _render_html используются
# только первые четыре. Значит, entities/flows в истории — балласт.
#
# Осторожно с мутацией: НЕ копируем весь report и не выкидываем из
# него ключи — так можно поломать обогащение, которое хранит тот же
# объект. Создаём НОВЫЙ dict с нужными ключами и кладём в историю его.
# Обогащение работает со своим report'ом (в EnrichView._report), не
# с этим.
print("== 1. history_view.py: slim report ==")

_apply(
    Path("pcap_triage_gui/views/history_view.py"),
    old=(
        "        ts = datetime.now()\n"
        "        # insert(0, ...) — новые записи сверху. Старые уезжают вниз\n"
        "        # по списку, визуально «проваливаются» в историю.\n"
        "        self._runs.insert(0, (ts, report))\n"
    ),
    new=(
        "        ts = datetime.now()\n"
        "\n"
        "        # В историю кладём урезанный dict, не весь report.\n"
        "        # Оригинал содержит entities и flows — они весят десятки МБ\n"
        "        # на больших pcap, а в _render_html не используются.\n"
        "        # Создаём НОВЫЙ dict, не мутируем исходный: тот же объект\n"
        "        # report живёт в EnrichView, и его нельзя ломать.\n"
        "        slim = {\n"
        "            \"summary\": report.get(\"summary\", {}),\n"
        "            \"contradictions\": report.get(\"contradictions\", []),\n"
        "            \"findings\": report.get(\"findings\", []),\n"
        "            \"provenance\": report.get(\"provenance\", {}),\n"
        "        }\n"
        "\n"
        "        # insert(0, ...) — новые записи сверху. Старые уезжают вниз\n"
        "        # по списку, визуально «проваливаются» в историю.\n"
        "        self._runs.insert(0, (ts, slim))\n"
    ),
    description="slim report в add_run",
)

# ВАЖНО: после slim-report метод refresh_current должен уметь
# принимать и метку от slim (там нет \"flows\", но _label_for и
# _count_enriched_iocs работают только с summary/provenance/findings —
# значит всё сходится).
#
# НО: если пользователь сначала обогащает, а потом — открой вкладку
# Истории, refresh_current перерисует HTML от slim'а. Обогащение
# мутирует оригинальный report, а не slim. Значит, секция
# «Обогащение» может не появиться. Это баг.
#
# Правильное решение: не слимить, а жить с размером, но обрезать
# историю до 10. Либо — синхронизировать. Проще первое.
print()
print("== 1b. Откат: заменяем slim на простое ограничение ==")
print("    (slim несовместим с обновлением после обогащения —")
print("     report в EnrichView и report в истории будут разными)")
print()

# Откатим slim — оставим исходное поведение, обрезку до 20 записей
# уже применили в прошлом скрипте.
_apply(
    Path("pcap_triage_gui/views/history_view.py"),
    old=(
        "        ts = datetime.now()\n"
        "\n"
        "        # В историю кладём урезанный dict, не весь report.\n"
        "        # Оригинал содержит entities и flows — они весят десятки МБ\n"
        "        # на больших pcap, а в _render_html не используются.\n"
        "        # Создаём НОВЫЙ dict, не мутируем исходный: тот же объект\n"
        "        # report живёт в EnrichView, и его нельзя ломать.\n"
        "        slim = {\n"
        "            \"summary\": report.get(\"summary\", {}),\n"
        "            \"contradictions\": report.get(\"contradictions\", []),\n"
        "            \"findings\": report.get(\"findings\", []),\n"
        "            \"provenance\": report.get(\"provenance\", {}),\n"
        "        }\n"
        "\n"
        "        # insert(0, ...) — новые записи сверху. Старые уезжают вниз\n"
        "        # по списку, визуально «проваливаются» в историю.\n"
        "        self._runs.insert(0, (ts, slim))\n"
    ),
    new=(
        "        ts = datetime.now()\n"
        "        # insert(0, ...) — новые записи сверху. Старые уезжают вниз\n"
        "        # по списку, визуально «проваливаются» в историю.\n"
        "        # Держим ссылку на оригинальный report, чтобы обогащение,\n"
        "        # мутирующее его in-place, было видно в истории.\n"
        "        self._runs.insert(0, (ts, report))\n"
    ),
    description="откат slim → оригинальный report",
)


# =============================================================================
# 2. Лог прогонов в файл
# =============================================================================
# При каждом успешном прогоне — одна строка в reports/gui-runs.log.
# Формат: timestamp, имя pcap, размер, packets, findings, contradictions,
# duration. Если что-то пойдёт не так на большом файле — будет видно,
# какой именно прогон был последним и сколько он занял.
print()
print("== 2. main_window.py: лог прогонов ==")

_apply(
    Path("pcap_triage_gui/main_window.py"),
    old=(
        "        # >>> ОБОГАЩЕНИЕ <<<\n"
        "        # Каждый новый прогон сбрасывает состояние вкладки «Обогащение»:\n"
        "        # кнопка «Обогатить» снова активна, таблица очищена.\n"
        "        if isinstance(report, dict) and hasattr(self, \"enrich_view\"):\n"
        "            self.enrich_view.set_report(report)\n"
        "        # >>> /ОБОГАЩЕНИЕ <<<\n"
    ),
    new=(
        "        # >>> ОБОГАЩЕНИЕ <<<\n"
        "        # Каждый новый прогон сбрасывает состояние вкладки «Обогащение»:\n"
        "        # кнопка «Обогатить» снова активна, таблица очищена.\n"
        "        if isinstance(report, dict) and hasattr(self, \"enrich_view\"):\n"
        "            self.enrich_view.set_report(report)\n"
        "        # >>> /ОБОГАЩЕНИЕ <<<\n"
        "\n"
        "        # >>> ЛОГ ПРОГОНОВ <<<\n"
        "        # Одна строка в reports/gui-runs.log. Помогает отследить,\n"
        "        # на каком именно файле что-то пошло не так, и когда.\n"
        "        # Ошибки логирования проглатываем: если диск полный или\n"
        "        # нет прав — GUI не должен падать из-за лога.\n"
        "        if isinstance(report, dict):\n"
        "            try:\n"
        "                import datetime as _dt\n"
        "                from pathlib import Path as _Path\n"
        "                prov = report.get(\"provenance\") or {}\n"
        "                pcap = prov.get(\"pcap_path\", \"?\") or \"?\"\n"
        "                name = pcap.rsplit(\"\\\\\", 1)[-1].rsplit(\"/\", 1)[-1]\n"
        "                s = report.get(\"summary\") or {}\n"
        "                log_path = _Path(\"reports\") / \"gui-runs.log\"\n"
        "                log_path.parent.mkdir(parents=True, exist_ok=True)\n"
        "                with log_path.open(\"a\", encoding=\"utf-8\") as f:\n"
        "                    f.write(\n"
        "                        f\"{_dt.datetime.now():%Y-%m-%d %H:%M:%S}  \"\n"
        "                        f\"{name}  \"\n"
        "                        f\"{s.get('size_bytes', 0) / 1024 / 1024:.1f}MB  \"\n"
        "                        f\"{s.get('packets', 0)}pkt  \"\n"
        "                        f\"{s.get('findings', 0)}find  \"\n"
        "                        f\"{s.get('contradictions', 0)}contra  \"\n"
        "                        f\"{s.get('duration_sec', 0):.1f}s\\n\"\n"
        "                    )\n"
        "            except Exception:\n"
        "                # Лог — не критичная часть, любые проблемы молча\n"
        "                # игнорируем.\n"
        "                pass\n"
        "        # >>> /ЛОГ ПРОГОНОВ <<<\n"
    ),
    description="лог прогонов в reports/gui-runs.log",
)


# =============================================================================
# 3. Ротация pcap-triage-error.log
# =============================================================================
# Runtime hook пишет в лог при каждом старте .exe. Без ротации файл
# вырастет за годы использования. Обрезаем при размере >5 МБ,
# оставляя последние 2.5 МБ.
print()
print("== 3. _runtime_hook.py: ротация лога ==")

_apply(
    Path("pcap_triage_gui/_runtime_hook.py"),
    old=(
        "_log_path = _log_dir / \"pcap-triage-error.log\"\n"
        "\n"
        "try:\n"
    ),
    new=(
        "_log_path = _log_dir / \"pcap-triage-error.log\"\n"
        "\n"
        "# --- Ротация: не даём файлу расти бесконечно ---\n"
        "# При размере >5 МБ обрезаем до последних 2.5 МБ. За\n"
        "# несколько лет использования файл не превратится в гигабайт.\n"
        "try:\n"
        "    if _log_path.exists() and _log_path.stat().st_size > 5 * 1024 * 1024:\n"
        "        _text = _log_path.read_text(encoding=\"utf-8\", errors=\"ignore\")\n"
        "        _log_path.write_text(_text[-2_500_000:], encoding=\"utf-8\")\n"
        "except Exception:\n"
        "    # Если не получилось обрезать — не критично, работаем дальше.\n"
        "    pass\n"
        "\n"
        "try:\n"
    ),
    description="ротация pcap-triage-error.log",
)


# =============================================================================
# ИТОГ
# =============================================================================
print()
print("=" * 72)
print("ГОТОВО")
print("=" * 72)
print()
print("Проверь синтаксис:")
print('  python -c "import ast; ast.parse(open(\'pcap_triage_gui/views/history_view.py\', encoding=\'utf-8\').read()); print(\'history OK\')"')
print('  python -c "import ast; ast.parse(open(\'pcap_triage_gui/main_window.py\', encoding=\'utf-8\').read()); print(\'mw OK\')"')
print('  python -c "import ast; ast.parse(open(\'pcap_triage_gui/_runtime_hook.py\', encoding=\'utf-8\').read()); print(\'hook OK\')"')
print()
print("Затем пересобери .exe и прогони 3-5 раз:")
print("  Remove-Item -Recurse -Force dist, build")
print("  python -m PyInstaller --clean --noconfirm pcap-triage.spec")
print("  .\\dist\\pcap-triage\\pcap-triage.exe")
print()
print("Проверь, что появился reports\\gui-runs.log с записями.")