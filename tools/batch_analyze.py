"""
Массовый прогон pipeline по всем pcap из папки FIRST-2015.

Ищет .pcap / .pcapng / .cap / snort.log.* рекурсивно,
прогоняет run_pipeline, сохраняет:
  - batch_results.json           — сводка по всем файлам
  - reports_batch/<name>.json    — полные отчёты для разбора

Результаты сохраняются после каждого файла — можно прервать
Ctrl+C без потери промежуточных данных.

Запуск:
    python batch_analyze.py | Tee-Object -FilePath batch_run.log
"""
from collections import Counter
from pathlib import Path
import json
import time

from pcap_triage.config import Config
from pcap_triage.pipeline import run_pipeline


ROOT = Path(r"C:\Users\a.grigoryev\Downloads\FIRST-2015_Hands-on_Network_Forensics_PCAP")
OUT = Path("batch_results.json")
REPORTS_DIR = Path("reports_batch")


def _is_pcap(path: Path) -> bool:
    if path.suffix.lower() in (".pcap", ".pcapng", ".cap"):
        return True
    if path.name.startswith("snort.log."):
        return True
    return False


def _safe_name(path: Path) -> str:
    """Уникальное имя для отчёта — путь через __, символы . → _."""
    rel = path.relative_to(ROOT)
    parts = list(rel.parts)
    name = "__".join(parts).replace(".", "_")
    return name[:200]


def _save_summary(results: list[dict]) -> None:
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def _save_report(report: dict, path: Path) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    out = REPORTS_DIR / f"{_safe_name(path)}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return out


def main() -> None:
    if not ROOT.exists():
        print(f"Папка не найдена: {ROOT}")
        return

    candidates = sorted(
        p for p in ROOT.rglob("*") if p.is_file() and _is_pcap(p)
    )
    print(f"Найдено pcap: {len(candidates)}")
    print(f"Отчёты: {REPORTS_DIR.resolve()}")
    print()

    config = Config(
        flow_report_top_n=50,
        entities_top_n=20,
    )
    results: list[dict] = []

    try:
        for i, path in enumerate(candidates, 1):
            rel = path.relative_to(ROOT)
            size_mb = path.stat().st_size / 1024 / 1024

            print(f"[{i}/{len(candidates)}] {rel}  ({size_mb:.1f} MB)")

            try:
                t0 = time.time()
                report = run_pipeline(path, config)
                elapsed = time.time() - t0
                report_path = _save_report(report, path)
            except Exception as e:
                print(f"    ERROR: {type(e).__name__}: {e}")
                results.append({
                    "path": str(rel),
                    "size_mb": round(size_mb, 2),
                    "error": f"{type(e).__name__}: {e}",
                })
                _save_summary(results)
                continue

            s = report["summary"]
            finding_types = Counter(f["type"] for f in report["findings"])

            print(
                f"    packets={s['packets']:,}  flows={s['flows']}  "
                f"findings={s['findings']}  {elapsed:.1f}s"
            )
            for ft, c in finding_types.most_common():
                print(f"      {ft}: {c}")

            results.append({
                "path": str(rel),
                "report_file": report_path.name,
                "size_mb": round(size_mb, 2),
                "packets": s["packets"],
                "flows": s["flows"],
                "findings": s["findings"],
                "finding_types": dict(finding_types),
                "elapsed_sec": round(elapsed, 2),
            })
            _save_summary(results)

    except KeyboardInterrupt:
        print()
        print("Прервано пользователем (Ctrl+C).")
        print(f"Промежуточные результаты сохранены: {OUT}")

    # --- итог ---
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    ok = [r for r in results if "error" not in r]
    err = [r for r in results if "error" in r]

    print(f"Обработано:  {len(ok)}")
    print(f"Ошибок:      {len(err)}")
    print(f"Находок:     {sum(r['findings'] for r in ok)}")
    print(f"Пакетов:     {sum(r['packets'] for r in ok):,}")
    print(f"Время:       {sum(r['elapsed_sec'] for r in ok):.1f}s")

    # Сводка по типам
    total_types: Counter = Counter()
    for r in ok:
        for ft, c in r.get("finding_types", {}).items():
            total_types[ft] += c
    if total_types:
        print()
        print("Findings по типам (суммарно):")
        for ft, c in total_types.most_common():
            print(f"  {ft:25}  {c}")

    # Топ по числу findings
    top = sorted(ok, key=lambda r: -r["findings"])[:15]
    if top:
        print()
        print("Топ-15 pcap по числу findings:")
        print(f"  {'findings':>8}  {'packets':>10}  path")
        for r in top:
            print(f"  {r['findings']:>8}  {r['packets']:>10,}  {r['path']}")

    # Топ по "редким" типам — DGA, cloud_tunnel, suspicious_port, script_download
    # Это те, где мало случаев и легко искать FP глазами.
    print()
    print("Топ pcap по 'редким' типам (DGA, cloud_tunnel, suspicious_port, ssh):")
    rare_types = {"dga_domain", "cloud_tunnel_domain", "suspicious_port"}
    for r in ok:
        ft = r.get("finding_types", {})
        rare_count = sum(v for k, v in ft.items() if k in rare_types)
        if rare_count >= 5:
            print(f"  {rare_count:>4} rare  {r['path']}")
            for k in rare_types:
                if k in ft:
                    print(f"          {k}: {ft[k]}")

    if err:
        print()
        print("Ошибки:")
        for r in err:
            print(f"  {r['path']}: {r['error']}")

    print()
    print(f"Полный вывод:        {OUT}")
    print(f"Отчёты для разбора:  {REPORTS_DIR.resolve()}")


if __name__ == "__main__":
    main()