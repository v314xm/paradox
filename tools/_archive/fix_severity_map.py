"""
Fix #3: добавь пропущенные типы в _SEVERITY_BY_TYPE.

Детекторы пишут типы, которых нет в карте:
  - cloud_tunnel_domain  (cloud_tunnel.py) — в карте только "cloud_tunnel"
  - smtp_spam            (smtp_spam.py)
  - sni_without_dns      (sni_mismatch.py) — в карте только "sni_mismatch"

Без явных записей они падают в default "medium". Явные записи делают
намерение очевидным и ловятся test_severity_map.py.

Идемпотентно.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS_PY = REPO_ROOT / "paradox" / "models.py"


# (anchor, additions) — anchor уже присутствует, additions вставляем после
INSERTIONS = [
    (
        '    "cloud_tunnel": "medium",\n',
        '    "cloud_tunnel_domain": "medium",\n',
    ),
    (
        '    "dga_domain": "medium",\n',
        '    "smtp_spam": "medium",\n'
        '    "sni_without_dns": "medium",\n',
    ),
]


def main() -> int:
    if not MODELS_PY.exists():
        print(f"ERROR: {MODELS_PY} not found", file=sys.stderr)
        return 1

    source = MODELS_PY.read_text(encoding="utf-8")

    if (
        '"cloud_tunnel_domain"' in source
        and '"smtp_spam"' in source
        and '"sni_without_dns"' in source
    ):
        print("[SKIP] all three types already in _SEVERITY_BY_TYPE")
        return 0

    for anchor, additions in INSERTIONS:
        if anchor not in source:
            print(
                f"ERROR: якорь не найден в models.py:\n  {anchor!r}",
                file=sys.stderr,
            )
            return 2
        if additions.strip() in source:
            continue
        source = source.replace(anchor, anchor + additions, count=1)
        for line in additions.rstrip().split("\n"):
            print(f"  + {line.strip()}")

    MODELS_PY.write_text(source, encoding="utf-8")
    print(f"[OK] _SEVERITY_BY_TYPE расширен в "
          f"{MODELS_PY.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
