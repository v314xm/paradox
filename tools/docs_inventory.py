"""Инвентаризация проекта для документации (v1.2.0)."""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _ast_stats(filepath: Path) -> dict:
    """Классы, функции, строки — из AST."""
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        return {"classes": [], "functions": [], "lines": 0}
    classes = []
    functions = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, ast.FunctionDef):
            functions.append(node.name)
    lines = len(filepath.read_text(encoding="utf-8").splitlines())
    return {"classes": classes, "functions": functions, "lines": lines}


def _count_tests(path: Path) -> int:
    """Количество test_* функций в файле."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        return 0
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    )


def main():
    print("=" * 70)
    print(" PARADOX v1.2.0 — инвентаризация")
    print("=" * 70)

    # Версии
    from paradox import __version__ as core_ver
    from paradox_gui import __version__ as gui_ver
    print(f"\nВерсии: core={core_ver}, gui={gui_ver}")

    # Пакет paradox/
    print("\n## Пакет paradox/")
    total_core = 0
    for f in sorted((ROOT / "paradox").rglob("*.py")):
        if "__pycache__" in f.parts:
            continue
        rel = f.relative_to(ROOT / "paradox")
        st = _ast_stats(f)
        total_core += st["lines"]
        if st["lines"] > 20:
            print(f"  {rel}: {st['lines']} строк")
    print(f"  ВСЕГО: {total_core} строк")

    # GUI
    print("\n## Пакет paradox_gui/")
    total_gui = 0
    for f in sorted((ROOT / "paradox_gui").rglob("*.py")):
        if "__pycache__" in f.parts:
            continue
        rel = f.relative_to(ROOT / "paradox_gui")
        st = _ast_stats(f)
        total_gui += st["lines"]
        if st["lines"] > 50:
            print(f"  {rel}: {st['lines']} строк")
    print(f"  ВСЕГО: {total_gui} строк")

    # Детекторы
    print("\n## Детекторы (DETECTORS)")
    from paradox.pipeline import DETECTORS, EXTRACTORS
    for d in DETECTORS:
        print(f"  - {d.name}")

    # Экстракторы
    print("\n## Экстракторы (EXTRACTORS)")
    for e in EXTRACTORS:
        print(f"  - {e.name} (layer {getattr(e, 'layer', '?')})")

    # Правила
    print("\n## Contradiction Rules (RULES)")
    from paradox.contradictions.registry import RULES
    for r in RULES:
        print(f"  - {type(r).__name__}: severity_base={r.severity_base}")

    # GUI вкладки
    print("\n## GUI вкладки")
    from paradox_gui.main_window import TAB_TITLES
    for i, t in enumerate(TAB_TITLES):
        print(f"  {i + 1}. {t}")

    # Тесты
    print("\n## Тесты")
    tests_dir = ROOT / "tests"
    total_tests = 0
    for f in sorted(tests_dir.glob("test_*.py")):
        n = _count_tests(f)
        total_tests += n
        print(f"  {f.name}: {n} тестов")
    print(f"  ВСЕГО: {total_tests} тестов в {len(list(tests_dir.glob('test_*.py')))} файлах")

    # Enrichment провайдеры
    print("\n## Enrichment провайдеры")
    from paradox.integrations.registry import REGISTRY
    for name in sorted(REGISTRY):
        print(f"  - {name}")


if __name__ == "__main__":
    sys.exit(main())
