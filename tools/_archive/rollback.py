"""
Откат всех изменений через git checkout.

Требует git. Если проект не под git — восстанови руками из списка
FILES_TO_REVERT.

  python tools/rollback.py
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FILES_TO_REVERT = [
    "paradox/models.py",
    "paradox/reporters/ioc_reporter.py",
    "paradox_gui/views/settings_view.py",
]

FILES_TO_DELETE = [
    "tests/test_severity_map.py",
    "tests/test_gui_severity_sync.py",
]


def main() -> int:
    try:
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=REPO_ROOT, check=True, capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: не git-репозиторий. Восстанови вручную:",
              file=sys.stderr)
        for f in FILES_TO_REVERT:
            print(f"  revert: {f}", file=sys.stderr)
        for f in FILES_TO_DELETE:
            print(f"  delete: {f}", file=sys.stderr)
        return 1

    rc = subprocess.run(
        ["git", "checkout", "--"] + FILES_TO_REVERT, cwd=REPO_ROOT,
    ).returncode
    if rc != 0:
        return rc

    for f in FILES_TO_DELETE:
        p = REPO_ROOT / f
        if p.exists():
            p.unlink()
            print(f"removed {f}")

    print("[OK] откат выполнен")
    return 0


if __name__ == "__main__":
    sys.exit(main())
