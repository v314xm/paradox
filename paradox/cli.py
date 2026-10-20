import argparse
import sys
from pathlib import Path

from paradox.config import Config
from paradox.pipeline import run_pipeline
from paradox.reporters.json_reporter import write_json, write_markdown


def _ask_pcap_path() -> Path:
    while True:
        raw = input("Путь к pcap-файлу: ").strip().strip("'\"")
        if not raw:
            print("Пусто. Попробуй ещё раз.")
            continue
        p = Path(raw).expanduser()
        if not p.exists():
            print(f"Не найдено: {p}")
            continue
        if not p.is_file():
            print(f"Это не файл: {p}")
            continue
        return p


def _safe_stem(pcap_path: Path) -> str:
    """
    Безопасный stem для дефолтного имени отчёта.

    Точки → подчёркивания: `snort_log.1425892283.pcap` даёт
    `snort_log_1425892283_pcap`, а не `snort_log.1425892283`. Второй
    вариант с `.report.json` на конце выглядит как расширение и
    ломает `Path.with_suffix` / автодополнение.
    """
    return pcap_path.name.replace(".", "_")[:80]


def _resolve_output(
    out_arg: Path | None, pcap_path: Path, config: Config,
) -> Path:
    """
    Куда писать JSON. Возвращает путь к файлу (не к директории).

    Правила:
      без -o                        → config.output_dir/<stem>.report.json
      -o dir/ или существующая dir  → <dir>/<stem>.report.json
      -o path/to/file               → ровно этот файл, .json добавляется,
                                       если у пути вообще нет расширения

    Родительская директория создаётся. Случай «-o указывает на
    существующую директорию» раньше падал с PermissionError —
    write_json пытался открыть директорию как файл.
    """
    stem = _safe_stem(pcap_path)

    if out_arg is None:
        out = config.output_dir / f"{stem}.report.json"
    else:
        out_arg = out_arg.expanduser()
        # Директорией считаем либо существующую папку, либо путь
        # с завершающим слешем (папка может ещё не существовать).
        raw = str(out_arg)
        is_dir_hint = raw.endswith(("/", "\\"))
        if out_arg.is_dir() or is_dir_hint:
            out = out_arg / f"{stem}.report.json"
        else:
            out = out_arg
            # Добавляем .json только если расширения нет совсем.
            # `foo.bar` оставляем как есть — это осознанный выбор юзера.
            if not out.suffix:
                out = out.with_suffix(".json")

    out.parent.mkdir(parents=True, exist_ok=True)
    return out


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="paradox")
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Обогатить findings через Shodan InternetDB (требует сети)",
    )
    parser.add_argument(
        "pcap", nargs="?", type=Path, default=None,
        help="path to pcap file (если не указан — спросит интерактивно)",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help=(
            "куда писать отчёты: файл (foo.json) или директория (foo/). "
            "По умолчанию — reports/<pcap>.report.json + .md рядом"
        ),
    )
    args = parser.parse_args(argv)

    pcap_path = args.pcap
    if pcap_path is None:
        pcap_path = _ask_pcap_path()
    else:
        pcap_path = pcap_path.expanduser()
        if not pcap_path.exists():
            print(f"file not found: {pcap_path}", file=sys.stderr)
            sys.exit(2)

    config = Config()
    report = run_pipeline(pcap_path, config)

    # Обогащение findings (опционально, --enrich)
    if args.enrich:
        from paradox.integrations.pipeline import enrich_findings

        print("  Обогащение через Threat Intel...")
        try:
            enrich_stats = enrich_findings(report["findings"], config)
            report["enrichment_stats"] = enrich_stats

            print(
                f"  IOC: {enrich_stats['iocs_total']} "
                f"(обогащено {enrich_stats['iocs_enriched']}, "
                f"кэш: {enrich_stats['cache_hits']}, "
                f"вызовов: {enrich_stats['provider_calls']}, "
                f"ошибок: {enrich_stats['errors']})"
            )
        except Exception as e:
            print(f"  Обогащение не удалось: {type(e).__name__}: {e}",
                  file=sys.stderr)
            report["enrichment_stats"] = {"error": str(e)}

    out = _resolve_output(args.output, pcap_path, config)
    write_json(report, out)

    md_out = out.with_suffix(".md")
    write_markdown(report, md_out)

    s = report["summary"]
    print()
    print(f"packets:            {s['packets']}")
    print(f"unique DNS queries: {s['unique_dns_queries']}")
    print(f"NXDOMAIN count:     {s['nxdomain_count']}")
    print(f"flows:              {s['flows']}")
    print(f"findings:           {s['findings']}")
    if s["extractor_errors"]:
        print(f"extractor errors:   {s['extractor_errors']}")
    print(f"report JSON:        {out}")
    print(f"report Markdown:    {md_out}")