import argparse
import sys
from pathlib import Path

from pcap_triage.config import Config
from pcap_triage.pipeline import run_pipeline
from pcap_triage.reporters.json_reporter import write_json, write_markdown


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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pcap_triage")
    parser.add_argument(
        "pcap", nargs="?", type=Path, default=None,
        help="path to pcap file (если не указан — спросит интерактивно)",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="output JSON path (default: reports/<name>.report.json)",
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

    safe_name = pcap_path.name.replace(".", "_")[:80]
    out = args.output or (config.output_dir / f"{safe_name}.report.json")
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