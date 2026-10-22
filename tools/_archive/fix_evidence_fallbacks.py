"""
Fix #1: Finding.__post_init__ fallback на src_ips и top_dst_ips.

Проблема: детекторы пишут evidence в форматах, которые
__post_init__ не понимает:
  - suspicious_port: evidence["src_ips"] = ["10.0.0.1", ...]
  - ja3_malware:     evidence["top_dst_ips"] = [{"ip": ..., "count": ...}, ...]

Из-за этого src_ip / dst_ip остаются None — entities.py не может
привязать finding к хосту, жертва не тегируется.

Идемпотентно.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS_PY = REPO_ROOT / "paradox" / "models.py"


OLD_BLOCK = (
    '        if self.src_ip is None:\n'
    '            self.src_ip = (\n'
    '                ev.get("src_ip")\n'
    '                or _first_ip_from_aggregated(ev.get("top_src_ips"))\n'
    '            )\n'
    '        if self.dst_ip is None:\n'
    '            self.dst_ip = (\n'
    '                ev.get("dst_ip") or _first_from_list(ev.get("dst_ips"))\n'
    '            )'
)

NEW_BLOCK = (
    '        if self.src_ip is None:\n'
    '            self.src_ip = (\n'
    '                ev.get("src_ip")\n'
    '                or _first_ip_from_aggregated(ev.get("top_src_ips"))\n'
    '                or _first_ip_from_aggregated(ev.get("src_ips"))\n'
    '            )\n'
    '        if self.dst_ip is None:\n'
    '            self.dst_ip = (\n'
    '                ev.get("dst_ip")\n'
    '                or _first_ip_from_aggregated(ev.get("dst_ips"))\n'
    '                or _first_ip_from_aggregated(ev.get("top_dst_ips"))\n'
    '            )'
)


def main() -> int:
    if not MODELS_PY.exists():
        print(f"ERROR: {MODELS_PY} not found", file=sys.stderr)
        return 1

    source = MODELS_PY.read_text(encoding="utf-8")

    if 'ev.get("src_ips")' in source and 'ev.get("top_dst_ips")' in source:
        print("[SKIP] evidence fallbacks already applied")
        return 0

    if OLD_BLOCK not in source:
        print(
            "ERROR: не нашёл ожидаемый блок в models.py.\n"
            "Возможно, файл уже правили. Текущий __post_init__ "
            "не совпадает с ожидаемым:",
            file=sys.stderr,
        )
        print(OLD_BLOCK, file=sys.stderr)
        return 2

    MODELS_PY.write_text(
        source.replace(OLD_BLOCK, NEW_BLOCK, count=1),
        encoding="utf-8",
    )
    print(f"[OK] патч применён к {MODELS_PY.relative_to(REPO_ROOT)}")
    print("  + src_ip ← evidence.src_ips (fallback)")
    print("  + dst_ip ← evidence.top_dst_ips (fallback)")
    print("  * dst_ips теперь через _first_ip_from_aggregated "
          "(поддержка list[dict])")
    return 0


if __name__ == "__main__":
    sys.exit(main())
