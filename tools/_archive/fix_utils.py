from __future__ import annotations

from pathlib import Path

DRY_RUN = False


class FixError(RuntimeError): pass


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write(path: Path, text: str) -> None:
    if DRY_RUN:
        print(f"  [dry-run] would write: {path}")
        return
    path.write_text(text, encoding="utf-8", newline="\n")


def patch(root: Path, rel_path: str, old: str, new: str, *, count: int = 1, required: bool = True) -> bool:
    path = root / rel_path
    if not path.exists():
        raise FixError(f"{rel_path}: file not found")
    text = _read(path)

    n_old = text.count(old)

    # 1. Если старого кода нет, проверяем, может быть новый уже там?
    if n_old == 0:
        if new and new in text:
            return False  # Уже применено
        if not new and old not in text:
            return False  # Уже удалено
        if not required:
            return False
        raise FixError(f"{rel_path}: neither old nor new found — look for: {old[:80]!r}")

    # 2. Если старого кода больше, чем ожидалось (защита от дублей)
    if n_old != count:
        raise FixError(f"{rel_path}: expected {count} occurrence(s), found {n_old}")

    # 3. Применяем замену
    new_text = text.replace(old, new)
    if new_text == text:
        return False
    _write(path, new_text)
    return True
