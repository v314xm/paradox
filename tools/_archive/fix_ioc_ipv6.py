"""
Fix #4: _looks_like_ip не видит IPv6.

Из-за этого iocs.txt / iocs.csv / suricata.rules / queries.txt теряют
все IPv6 IOC (2001:db8::1, fe80::1, ::1), хотя IPv6-сущности есть
в отчёте.

Идемпотентно.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IOC_REPORTER = REPO_ROOT / "paradox" / "reporters" / "ioc_reporter.py"


OLD_FUNC = (
    'def _looks_like_ip(s: str) -> bool:\n'
    '    """Быстрая проверка \'похоже на IPv4\'."""\n'
    '    if not s or "." not in s:\n'
    '        return False\n'
    '    parts = s.split(".")\n'
    '    if len(parts) != 4:\n'
    '        return False\n'
    '    try:\n'
    '        return all(0 <= int(p) <= 255 for p in parts)\n'
    '    except ValueError:\n'
    '        return False'
)

NEW_FUNC = (
    'def _looks_like_ip(s: str) -> bool:\n'
    '    """Проверка IPv4/IPv6 через ipaddress."""\n'
    '    if not s:\n'
    '        return False\n'
    '    try:\n'
    '        ipaddress.ip_address(s)\n'
    '        return True\n'
    '    except ValueError:\n'
    '        return False'
)


def main() -> int:
    if not IOC_REPORTER.exists():
        print(f"ERROR: {IOC_REPORTER} not found", file=sys.stderr)
        return 1

    source = IOC_REPORTER.read_text(encoding="utf-8")

    if "ipaddress.ip_address" in source:
        print("[SKIP] IPv6 support already added")
        return 0

    if OLD_FUNC not in source:
        print(
            "ERROR: старый _looks_like_ip не найден — файл уже правили?",
            file=sys.stderr,
        )
        return 2

    new_source = source.replace(OLD_FUNC, NEW_FUNC, count=1)

    if "import ipaddress" not in new_source:
        # Вставляем импорт рядом с остальными stdlib
        new_source = new_source.replace(
            "import io\nimport json",
            "import io\nimport ipaddress\nimport json",
            count=1,
        )

    IOC_REPORTER.write_text(new_source, encoding="utf-8")
    print(f"[OK] {IOC_REPORTER.relative_to(REPO_ROOT)}:")
    print("  + import ipaddress")
    print("  * _looks_like_ip теперь handles IPv4 и IPv6")
    return 0


if __name__ == "__main__":
    sys.exit(main())
