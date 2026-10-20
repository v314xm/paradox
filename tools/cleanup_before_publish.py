"""Очистка проекта перед публикацией на GitHub.

Dry-run: показывает что будет удалено, спрашивает подтверждение.
Защищены: исходный код (paradox/, paradox_gui/, tests/, tools/*.py),
README, pyproject.toml, .git.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Что удалять — паттерны и конкретные пути
DELETE_PATTERNS = [
    "*.pcap",
    "*.pcapng",
    "*.cap",
    "*.pcap.bak",
    "*.pcap.part1",
    "*.pcap.part2",
    "*_part1.pcap",
    "*_part2.pcap",
    "*.log",
    "*.tmp",
    "*.bak",
    "*.orig",
    ".DS_Store",
    "Thumbs.db",
]

DELETE_DIRS = [
    "reports",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".autofix-backup",
    "build",
    "dist",
    "*.egg-info",
]

DELETE_TOP_LEVEL = [
    "core_dump.txt",
    "gui_dump.txt",
    "diag_output.txt",
    "diag_warns.py",
    "project_tree.txt",
    "apply_review_fixes.py",
    "clean_fix.py",
    "dedupe_yara.py",
    "rename_project.py",
    "Paradox-error.log",
]

# Что НЕ трогать никогда (страховка)
PROTECTED = [
    "paradox",
    "paradox_gui",
    "tests",
    "tools",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    ".git",
    ".gitignore",
    ".venv",
    "venv",
    "paradox_gui.spec",
]


def find_pycache_dirs() -> list[Path]:
    """Все __pycache__ рекурсивно, но не в .venv."""
    out = []
    for p in ROOT.rglob("__pycache__"):
        if ".venv" in p.parts or "venv" in p.parts:
            continue
        out.append(p)
    return out


def collect_targets() -> tuple[list[Path], list[Path]]:
    """Собрать файлы и директории для удаления."""
    files: set[Path] = set()
    dirs: set[Path] = set()

    # 1. Файлы по паттернам в корне
    for pattern in DELETE_PATTERNS:
        for p in ROOT.glob(pattern):
            if p.is_file():
                files.add(p)

    # 2. Директории по паттернам в корне
    for pattern in DELETE_DIRS:
        for p in ROOT.glob(pattern):
            if p.is_dir():
                dirs.add(p)

    # 3. Конкретные файлы верхнего уровня
    for name in DELETE_TOP_LEVEL:
        p = ROOT / name
        if p.is_file():
            files.add(p)
        elif p.is_dir():
            dirs.add(p)

    # 4. __pycache__ рекурсивно
    for p in find_pycache_dirs():
        dirs.add(p)

    # 5. Отчёты в подпапках (reports/, .cache/)
    for p in ROOT.rglob("*.json"):
        # Пропускаем tests и .venv
        if "tests" in p.parts or ".venv" in p.parts:
            continue
        # Только отчёты Paradox
        if p.name.endswith(".report.json") or p.parent.name == "reports":
            files.add(p)

    # 6. Защита: убрать из списков всё что в PROTECTED
    def _is_protected(path: Path) -> bool:
        rel = path.relative_to(ROOT)
        parts = rel.parts
        if not parts:
            return True
        for protected in PROTECTED:
            if parts[0] == protected:
                return True
        # .gitignore не трогаем
        if path.name == ".gitignore":
            return True
        return False

    files = {f for f in files if not _is_protected(f)}
    dirs = {d for d in dirs if not _is_protected(d)}

    # 7. Убрать дубликаты: директории, содержащие другие директории из списка
    dirs_filtered = set()
    for d in sorted(dirs, key=lambda x: len(x.parts)):
        # Если родитель уже в списке — пропускаем
        if any(parent in dirs_filtered for parent in d.parents):
            continue
        dirs_filtered.add(d)

    return sorted(files), sorted(dirs_filtered)


def human_size(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n_bytes < 1024:
            return f"{n_bytes:.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} TB"


def dir_size(path: Path) -> int:
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def main():
    print("=" * 70)
    print(" Очистка проекта перед публикацией на GitHub")
    print("=" * 70)
    print(f"Корень: {ROOT}")
    print()

    files, dirs = collect_targets()

    if not files and not dirs:
        print("[OK] Нечего чистить — проект уже чистый.")
        return 0

    total_files_size = sum(f.stat().st_size for f in files if f.exists())
    total_dirs_size = sum(dir_size(d) for d in dirs)

    print(f"Файлов к удалению: {len(files)} ({human_size(total_files_size)})")
    for f in files[:30]:
        print(f"  FILE  {f.relative_to(ROOT)}  ({human_size(f.stat().st_size)})")
    if len(files) > 30:
        print(f"  ... и ещё {len(files) - 30} файлов")

    print()
    print(f"Директорий к удалению: {len(dirs)} ({human_size(total_dirs_size)})")
    for d in dirs[:20]:
        print(f"  DIR   {d.relative_to(ROOT)}/  ({human_size(dir_size(d))})")
    if len(dirs) > 20:
        print(f"  ... и ещё {len(dirs) - 20} директорий")

    print()
    print(f"ИТОГО освободится: {human_size(total_files_size + total_dirs_size)}")
    print()

    # Запрос подтверждения
    answer = input("Удалить всё это? [y/N]: ").strip().lower()
    if answer not in ("y", "yes", "да", "д"):
        print("Отменено. Ничего не тронуто.")
        return 0

    # Удаление
    print()
    print("Удаление...")
    deleted_files = 0
    deleted_dirs = 0
    errors = []

    for f in files:
        try:
            f.unlink()
            deleted_files += 1
        except OSError as e:
            errors.append((f, str(e)))

    for d in dirs:
        try:
            shutil.rmtree(d)
            deleted_dirs += 1
        except OSError as e:
            errors.append((d, str(e)))

    print(f"[OK] Удалено файлов: {deleted_files}")
    print(f"[OK] Удалено директорий: {deleted_dirs}")
    if errors:
        print(f"[WARN] Ошибок: {len(errors)}")
        for path, err in errors[:5]:
            print(f"  {path.relative_to(ROOT)}: {err}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
