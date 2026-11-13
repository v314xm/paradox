import argparse
import os
import sys
from pathlib import Path

from paradox import __version__
from paradox.config import Config
from paradox.errors import ParadoxInputError
from paradox.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    L,
    set_language,
)
from paradox.reporters.html_reporter import write_html
from paradox.reporters.json_reporter import write_json, write_markdown
from paradox.reporters.stix_reporter import write_stix

# Загружается лениво: импорт pipeline тянет scapy, который печатает
# предупреждение о libpcap даже для `--version`. Тесты патчат этот
# символ, поэтому он остаётся атрибутом модуля.
run_pipeline = None


def _pipeline():
    global run_pipeline
    if run_pipeline is None:
        from paradox.pipeline import run_pipeline as _run
        run_pipeline = _run
    return run_pipeline


def _ask_pcap_path() -> Path:
    while True:
        raw = input(L("Путь к pcap-файлу: ", "Path to the pcap file: "))
        raw = raw.strip().strip("'\"")
        if not raw:
            print(L("Пусто. Попробуй ещё раз.", "Empty. Try again."))
            continue
        p = Path(raw).expanduser()
        if not p.exists():
            print(L(f"Не найдено: {p}", f"Not found: {p}"))
            continue
        if not p.is_file():
            print(L(f"Это не файл: {p}", f"Not a file: {p}"))
            continue
        return p


def _lang_from_argv(argv: list[str]) -> str:
    """Язык из --lang до разбора аргументов.

    Нужен, чтобы `--help` печатался на выбранном языке: argparse
    собирает тексты помощи заранее.
    """
    for index, arg in enumerate(argv):
        if arg == "--lang" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--lang="):
            return arg.split("=", 1)[1]
    return DEFAULT_LANGUAGE


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
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    unknown = _lang_from_argv(raw_argv)
    if unknown in SUPPORTED_LANGUAGES:
        set_language(unknown)

    parser = argparse.ArgumentParser(prog="paradox")
    parser.add_argument(
        "--version",
        action="version",
        version=f"paradox {__version__}",
    )
    parser.add_argument(
        "--lang",
        choices=SUPPORTED_LANGUAGES,
        default=DEFAULT_LANGUAGE,
        help=L(
            "язык отчётов и сообщений (по умолчанию ru)",
            "language of reports and messages (default: ru)",
        ),
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help=L(
            "Обогатить findings через Shodan InternetDB (требует сети)",
            "Enrich findings via Shodan InternetDB (needs network)",
        ),
    )
    parser.add_argument(
        "--stix",
        action="store_true",
        help=L(
            "Дополнительно выгрузить STIX 2.1 bundle (рядом с JSON)",
            "Also write a STIX 2.1 bundle next to the JSON report",
        ),
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help=L(
            "Дополнительно HTML-отчёт (открыть в браузере, печать в PDF)",
            "Also write an HTML report (open in a browser, print to PDF)",
        ),
    )
    parser.add_argument(
        "--plugins",
        action="store_true",
        help=L(
            "Загрузить детекторы из ~/.paradox/plugins/*.py",
            "Load detectors from ~/.paradox/plugins/*.py",
        ),
    )
    parser.add_argument(
        "--behavioral",
        action="store_true",
        help=L(
            "Включить поведенческий анализ (Isolation Forest): усиливает "
            "rule-находки, совпавшие со статистическими выбросами, и "
            "помечает хосты с аномальным профилем (host_behavior_anomaly)",
            "Enable behavioural analysis (Isolation Forest): reinforces "
            "rule findings that coincide with statistical outliers and "
            "flags hosts with an anomalous profile (host_behavior_anomaly)",
        ),
    )
    parser.add_argument(
        "--tls-keylog",
        type=Path,
        default=None,
        metavar="PATH",
        help=L(
            "SSLKEYLOGFILE для расшифровки TLS: h2/HTTPS попадут в "
            "HTTP-объекты. По умолчанию берётся из $SSLKEYLOGFILE",
            "SSLKEYLOGFILE for TLS decryption: h2/HTTPS traffic lands in "
            "HTTP objects. Defaults to $SSLKEYLOGFILE",
        ),
    )
    parser.add_argument(
        "pcap", nargs="?", type=Path, default=None,
        help=L(
            "path to pcap file (если не указан — спросит интерактивно)",
            "path to the pcap file (asked interactively if omitted)",
        ),
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help=L(
            "куда писать отчёты: файл (foo.json) или директория (foo/). "
            "По умолчанию — reports/<pcap>.report.json + .md рядом",
            "where to write reports: a file (foo.json) or a directory "
            "(foo/). Default: reports/<pcap>.report.json plus .md next to it",
        ),
    )
    args = parser.parse_args(raw_argv)
    set_language(args.lang)

    pcap_path = args.pcap
    if pcap_path is None:
        pcap_path = _ask_pcap_path()
    else:
        pcap_path = pcap_path.expanduser()
        if not pcap_path.exists():
            print(
                L(f"файл не найден: {pcap_path}", f"file not found: {pcap_path}"),
                file=sys.stderr,
            )
            sys.exit(2)

    keylog = args.tls_keylog
    if keylog is None:
        env_keylog = os.environ.get("SSLKEYLOGFILE")
        keylog = Path(env_keylog) if env_keylog else None

    config = Config(
        plugins_enabled=args.plugins,
        behavioral_enabled=args.behavioral,
        tls_keylog_path=str(keylog) if keylog else None,
    )
    pipeline = _pipeline()

    try:
        report = pipeline(pcap_path, config)
    except ParadoxInputError as exc:
        print(L(f"ошибка входа: {exc}", f"input error: {exc}"), file=sys.stderr)
        sys.exit(3)

    # Обогащение findings (опционально, --enrich)
    if args.enrich:
        from paradox.integrations.pipeline import enrich_findings

        print(L("  Обогащение через Threat Intel...",
                "  Enriching via Threat Intel..."))
        try:
            enrich_stats = enrich_findings(report["findings"], config)
            report["enrichment_stats"] = enrich_stats

            print(
                L(
                    f"  IOC: {enrich_stats['iocs_total']} "
                    f"(обогащено {enrich_stats['iocs_enriched']}, "
                    f"кэш: {enrich_stats['cache_hits']}, "
                    f"вызовов: {enrich_stats['provider_calls']}, "
                    f"ошибок: {enrich_stats['errors']})",
                    f"  IOCs: {enrich_stats['iocs_total']} "
                    f"(enriched {enrich_stats['iocs_enriched']}, "
                    f"cache hits: {enrich_stats['cache_hits']}, "
                    f"provider calls: {enrich_stats['provider_calls']}, "
                    f"errors: {enrich_stats['errors']})",
                )
            )
        except Exception as e:
            print(
                L(
                    f"  Обогащение не удалось: {type(e).__name__}: {e}",
                    f"  Enrichment failed: {type(e).__name__}: {e}",
                ),
                file=sys.stderr,
            )
            report["enrichment_stats"] = {"error": str(e)}

    out = _resolve_output(args.output, pcap_path, config)
    write_json(report, out)

    md_out = out.with_suffix(".md")
    write_markdown(report, md_out)

    stix_out = None
    if args.stix:
        stix_out = out.with_suffix(".stix.json")
        write_stix(report, stix_out)

    html_out = None
    if args.html:
        html_out = out.with_suffix(".html")
        write_html(report, html_out)

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
    if stix_out is not None:
        print(f"report STIX:        {stix_out}")
    if html_out is not None:
        print(f"report HTML:        {html_out}")
