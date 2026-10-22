"""Общая утилита для патчей: безопасная замена строк в файлах."""
from __future__ import annotations

from pathlib import Path

DRY_RUN = False


class FixError(RuntimeError):
    pass


def set_dry_run(value: bool) -> None:
    global DRY_RUN
    DRY_RUN = value


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write(path: Path, text: str) -> None:
    if DRY_RUN:
        print(f"  [dry-run] would write: {path}")
        return
    path.write_text(text, encoding="utf-8", newline="\n")


def patch(
    root: Path, rel_path: str, old: str, new: str,
    *, count: int = 1, required: bool = True,
) -> bool:
    """Заменить old на new. Идемпотентна: повторный вызов → False.

    Защита: old не должен быть подстрокой new. Если old — префикс new
    (классика «добавили строку в конец блока»), после первого apply
    old всё ещё матчится, и повторный apply даёт дубль. Такой патч
    надо переписать: добавить в old закрывающий маркер (пустая строка,
    следующая секция) или вставлять new перед маркером, а не после.
    """
    if old in new:
        raise FixError(
            f"{rel_path}: 'old' is a substring of 'new' — not idempotent. "
            f"Add a closing marker (blank line, next key) to 'old'."
        )

    path = root / rel_path
    if not path.exists():
        raise FixError(f"{rel_path}: file not found")
    text = _read(path)
    n_old = text.count(old)

    if n_old == 0:
        if new and new in text:
            return False
        if not new:
            return False
        if not required:
            return False
        raise FixError(
            f"{rel_path}: neither old nor new found — "
            f"look for: {old[:80]!r}"
        )
    if n_old != count:
        raise FixError(
            f"{rel_path}: expected {count} occurrence(s), found {n_old}"
        )
    new_text = text.replace(old, new)
    if new_text == text:
        return False
    _write(path, new_text)
    return True


def assert_applied(root: Path, rel_path: str, marker: str) -> None:
    if DRY_RUN:
        return
    path = root / rel_path
    if not path.exists():
        raise FixError(f"{rel_path}: file not found (verify)")
    if marker not in path.read_text(encoding="utf-8"):
        raise FixError(
            f"{rel_path}: marker not found after apply — {marker[:80]!r}"
        )


def assert_not_present(root: Path, rel_path: str, marker: str) -> None:
    if DRY_RUN:
        return
    path = root / rel_path
    if marker in path.read_text(encoding="utf-8"):
        raise FixError(f"{rel_path}: marker still present — {marker[:80]!r}")
