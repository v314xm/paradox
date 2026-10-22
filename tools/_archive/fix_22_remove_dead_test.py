from pathlib import Path

FIX_ID = "fix_22"
TITLE = "Remove dead test_tls_parse.py"

def apply(root: Path) -> bool:
    path = root / "tests" / "test_tls_parse.py"
    if path.exists():
        path.unlink()
        return True
    return False
