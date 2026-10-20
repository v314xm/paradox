import json
from pathlib import Path


def write_json(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, sort_keys=True)


def write_markdown(report: dict, path) -> None:
    """Записать Markdown-версию отчёта."""
    from pathlib import Path

    from paradox.reporters.markdown_reporter import render_markdown

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))