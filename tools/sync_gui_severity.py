"""
Fix #2: синхронизируй severity-метки в _CONTRADICTIONS с ядром.

GUI показывает stale severity — пользователь видит "critical" в
Настройках, получает "medium" finding. Синхронизируем лейблы с
rule.severity_base.

На момент написания расхождения:
  SniCertMismatchRule:     high → medium
  ExpiredCertRule:         medium → low
  SniWithoutDnsRule:       high → medium
  DnsAnswerMismatchRule:   critical → medium

Идемпотентно.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_VIEW = REPO_ROOT / "paradox_gui" / "views" / "settings_view.py"


def main() -> int:
    if not SETTINGS_VIEW.exists():
        print(f"ERROR: {SETTINGS_VIEW} not found", file=sys.stderr)
        return 1

    # Загружаем core severity из реальных классов
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from paradox.contradictions.registry import RULES
    except ImportError as e:
        print(f"ERROR: cannot import RULES: {e}", file=sys.stderr)
        return 2

    core = {type(r).__name__: r.severity_base for r in RULES}
    source = SETTINGS_VIEW.read_text(encoding="utf-8")

    changes = []
    for rule_name, core_sev in core.items():
        # ("RuleName", "... — severity")
        pattern = re.compile(
            rf'("{re.escape(rule_name)}",\s+"[^"]*?)\s+—\s+'
            rf'(critical|high|medium|low|info)(")',
            re.MULTILINE,
        )
        m = pattern.search(source)
        if not m:
            print(f"[WARN] лейбл не найден: {rule_name}")
            continue
        gui_sev = m.group(2)
        if gui_sev == core_sev:
            continue

        new_block = f'{m.group(1)} — {core_sev}{m.group(3)}'
        source = pattern.sub(new_block, source, count=1)
        changes.append((rule_name, gui_sev, core_sev))

    if not changes:
        print("[SKIP] все severity-метки уже совпадают с ядром")
        return 0

    SETTINGS_VIEW.write_text(source, encoding="utf-8")
    print(f"[OK] {len(changes)} меток обновлено в "
          f"{SETTINGS_VIEW.relative_to(REPO_ROOT)}:")
    for name, old, new in changes:
        print(f"  {name}: {old} → {new}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
