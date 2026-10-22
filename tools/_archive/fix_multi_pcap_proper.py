"""Proper multi-pcap: extend run_pipeline instead of separate function."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE = REPO_ROOT / "paradox" / "pipeline.py"


def main():
    print("=" * 60)
    print(" fixing multi-pcap integration")
    print("=" * 60)

    src = PIPELINE.read_text(encoding="utf-8")

    # 1. Удалить сломанный run_multi_pipeline (если есть)
    start = src.find("def run_multi_pipeline(")
    if start >= 0:
        end = src.find("def run_pipeline(", start)
        if end > start:
            src = src[:start] + src[end:]
            print("[OK] removed broken run_multi_pipeline")

    # 2. Добавить импорт merge_capture_states (если нет)
    if "from paradox.multi_pcap import" not in src:
        old_imp = "from paradox.models import CaptureState\n"
        new_imp = old_imp + "from paradox.multi_pcap import merge_capture_states\n"
        if old_imp in src:
            src = src.replace(old_imp, new_imp, count=1)
            print("[OK] added import")
        else:
            print("[ERROR] cannot find models import", file=sys.stderr)
            return 1

    # 3. Заменить извлечение state на multi-совместимое
    old_state = (
        '    state = CaptureState()\n'
        '\n'
        '    _extract(\n'
        '        pcap_path, state, config,\n'
        '        should_stop=should_stop,\n'
        '        on_progress=on_progress,\n'
        '    )\n'
    )
    new_state = (
        '    # v1.2: multi-pcap — принимаем Path или list[Path]\n'
        '    if isinstance(pcap_path, list):\n'
        '        states = []\n'
        '        for _p in pcap_path:\n'
        '            _st = CaptureState()\n'
        '            _extract(\n'
        '                _p, _st, config,\n'
        '                should_stop=should_stop,\n'
        '                on_progress=on_progress,\n'
        '            )\n'
        '            states.append(_st)\n'
        '        state = merge_capture_states(states)\n'
        '    else:\n'
        '        state = CaptureState()\n'
        '        _extract(\n'
        '            pcap_path, state, config,\n'
        '            should_stop=should_stop,\n'
        '            on_progress=on_progress,\n'
        '        )\n'
    )
    if old_state in src:
        src = src.replace(old_state, new_state, count=1)
        print("[OK] run_pipeline accepts list[Path]")
    elif "isinstance(pcap_path, list)" in src:
        print("[SKIP] already applied")
    else:
        print("[ERROR] cannot find state extraction block", file=sys.stderr)
        return 1

    # 4. Provenance: обработать оба случая
    old_prov = (
        '        "provenance": {\n'
        '            "tool_version": __version__,\n'
        '            "pcap_path": str(pcap_path),\n'
        '            "pcap_sha256": sha256_file(pcap_path),\n'
        '        },\n'
    )
    new_prov = (
        '        "provenance": {\n'
        '            "tool_version": __version__,\n'
        '            "pcap_path": (\n'
        '                f"merged:{len(pcap_path)} files"\n'
        '                if isinstance(pcap_path, list)\n'
        '                else str(pcap_path)\n'
        '            ),\n'
        '            "pcap_sha256": (\n'
        '                "merged"\n'
        '                if isinstance(pcap_path, list)\n'
        '                else sha256_file(pcap_path)\n'
        '            ),\n'
        '            "merged_files": (\n'
        '                [str(p) for p in pcap_path]\n'
        '                if isinstance(pcap_path, list)\n'
        '                else None\n'
        '            ),\n'
        '        },\n'
    )
    if old_prov in src:
        src = src.replace(old_prov, new_prov, count=1)
        print("[OK] provenance handles multi-pcap")
    elif "merged_files" in src:
        print("[SKIP] provenance already fixed")
    else:
        print("[ERROR] cannot find provenance block", file=sys.stderr)
        return 1

    PIPELINE.write_text(src, encoding="utf-8")

    # 5. Проверка импорта
    print("\nVerifying import...")
    import importlib
    try:
        import paradox.pipeline
        importlib.reload(paradox.pipeline)
        print("[OK] pipeline.py imports successfully")
    except Exception as e:
        print(f"[ERROR] import failed: {type(e).__name__}: {e}", file=sys.stderr)
        print("\nРекомендация: откати руками через git:", file=sys.stderr)
        print("  git checkout paradox/pipeline.py", file=sys.stderr)
        return 1

    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
