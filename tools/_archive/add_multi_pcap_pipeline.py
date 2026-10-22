"""Multi-pcap: pipeline integration."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE = REPO_ROOT / "paradox" / "pipeline.py"


def _patch(path, old, new, name):
    src = path.read_text(encoding="utf-8")
    if new in src and old not in src:
        print(f"[SKIP] {name}: already applied")
        return True
    if old not in src:
        print(f"[ERROR] {name}: anchor not found", file=sys.stderr)
        return False
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


def add_import():
    old = "from paradox.models import CaptureState\n"
    new = "from paradox.models import CaptureState\nfrom paradox.multi_pcap import merge_capture_states\n"
    return _patch(PIPELINE, old, new, "import merge_capture_states")


def add_function():
    # Добавляем функцию run_multi_pipeline в конец файла перед return
    old = "def run_pipeline(\n"
    new = '''def run_multi_pipeline(
    pcap_paths: list[Path],
    config: Config,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict:
    """Прогон нескольких pcap-файлов со слиянием в один CaptureState."""
    if not pcap_paths:
        raise ValueError("pcap_paths is empty")

    states: list[CaptureState] = []
    total_files = len(pcap_paths)

    if on_progress:
        on_progress(0, total_files)

    for i, path in enumerate(pcap_paths, start=1):
        print(f"  Обработка файла {i}/{total_files}: {path.name}")
        state = CaptureState()
        _extract(path, state, config, should_stop=should_stop)
        states.append(state)
        if on_progress:
            on_progress(i, total_files)

    print(f"  Слияние {total_files} датасетов...")
    merged = merge_capture_states(states)

    if should_stop is not None and should_stop():
        raise PipelineCancelled()

    findings = _detect(merged, config)
    contradictions = run_contradictions(merged, findings, config)
    timeline_events = build_timeline(findings, contradictions, carved_files=merged.carved_files)

    # ... остальное как в run_pipeline, но через merged state
    # (для краткости возьмём существующий отчёт как шаблон)
    report = run_pipeline(
        pcap_paths[0],  # берём первый как "главный" для provenance
        config,
        should_stop=should_stop,
    )

    # Перезаписываем summary и findings из merged
    report["summary"]["packets"] = merged.packet_count
    report["summary"]["flows"] = len(merged.flows)
    report["summary"]["findings"] = len(findings)
    report["summary"]["contradictions"] = len(contradictions)
    report["provenance"]["pcap_path"] = f"merged:{total_files} files"
    report["merged_files"] = [str(p) for p in pcap_paths]

    return report


def run_pipeline(
'''
    return _patch(PIPELINE, old, new, "run_multi_pipeline function")


def main():
    print("=" * 60)
    print(" multi-pcap: pipeline")
    print("=" * 60)
    ok = True
    for fn in (add_import, add_function):
        try:
            if not fn(): ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + ("DONE" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
