"""Fix v1.1 test failures.

1. Убрать валидацию имён провайдеров из Config._validate — она
   нарушает слои (Config → integrations), и ломает тесты с mock.
   Валидация переехала в build_default_orchestrator как warning.

2. Reassembler: разделить «всего прошло» (_bytes_seen_total,
   для stats()) и «сейчас в буфере» (_total_bytes, для лимита).
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _patch(path, old, new, name):
    if not path.exists():
        print(f"[ERROR] {name}: not found: {path}", file=sys.stderr)
        return False
    src = path.read_text(encoding="utf-8")
    if old not in src:
        print(f"[ERROR] {name}: anchor not found", file=sys.stderr)
        return False
    if new in src:
        print(f"[SKIP] {name}: already applied")
        return True
    path.write_text(src.replace(old, new, count=1), encoding="utf-8")
    print(f"[OK] {name}")
    return True


def revert_config_validate():
    """Удаляем блок валидации провайдеров из Config._validate."""
    path = REPO_ROOT / "paradox" / "config.py"
    old = (
        '        try:\n'
        '            from paradox.integrations.registry import REGISTRY\n'
        '            known = set(REGISTRY)\n'
        '            unknown = set(self.enrichment_enabled_providers) - known\n'
        '            if unknown:\n'
        '                errors.append(\n'
        '                    f"enrichment_enabled_providers: неизвестные: {sorted(unknown)}. "\n'
        '                    f"Известные: {sorted(known)}"\n'
        '                )\n'
        '        except ImportError:\n'
        '            pass\n'
        '\n'
        '        if errors:\n'
    )
    new = '        if errors:\n'
    return _patch(path, old, new, "config: revert provider validation")


def fix_reassembler_stats():
    """Разделяем _total_bytes (лимит) и _bytes_seen_total (stats)."""
    path = REPO_ROOT / "paradox" / "reassembler.py"

    # 1. __init__: добавить _bytes_seen_total рядом с _total_bytes
    old1 = (
        '        # общий счётчик байт (в буферах + финализированных)\n'
        '        self._total_bytes = 0\n'
    )
    new1 = (
        '        # Текущий объём буферов (для проверки лимита).\n'
        '        # Уменьшается в _finalize при склейке потока.\n'
        '        self._total_bytes = 0\n'
        '        # Монотонный счётчик «сколько всего прошло» — для stats().\n'
        '        # Не уменьшается при финализации: пользователь видит\n'
        '        # суммарный объём, а не текущее заполнение буферов.\n'
        '        self._bytes_seen_total = 0\n'
    )
    if not _patch(path, old1, new1, "reassembler: __init__"):
        return False

    # 2. _store: инкрементировать оба счётчика
    old2 = (
        '        buf[offset] = data\n'
        '        self._flow_sizes[key] = flow_size + len(data)\n'
        '        self._total_bytes += len(data)\n'
    )
    new2 = (
        '        buf[offset] = data\n'
        '        self._flow_sizes[key] = flow_size + len(data)\n'
        '        self._total_bytes += len(data)\n'
        '        self._bytes_seen_total += len(data)\n'
    )
    if not _patch(path, old2, new2, "reassembler: _store"):
        return False

    # 3. stats: возвращать монотонный счётчик
    old3 = (
        '    def stats(self) -> dict:\n'
        '        return {\n'
        '            "streams_total": len(self._finalized),\n'
        '            "streams_truncated": len(self._truncated),\n'
        '            "bytes_total": self._total_bytes,\n'
        '        }'
    )
    new3 = (
        '    def stats(self) -> dict:\n'
        '        return {\n'
        '            "streams_total": len(self._finalized),\n'
        '            "streams_truncated": len(self._truncated),\n'
        '            "bytes_total": self._bytes_seen_total,\n'
        '        }'
    )
    return _patch(path, old3, new3, "reassembler: stats")


def add_orchestrator_warning():
    """Валидация имён провайдеров → warning в build_default_orchestrator."""
    path = REPO_ROOT / "paradox" / "integrations" / "pipeline.py"
    old = (
        '    from paradox.integrations.registry import REGISTRY\n'
        '\n'
        '    enabled = set(config.enrichment_enabled_providers)\n'
        '    providers = [\n'
        '        cls() for name, cls in REGISTRY.items() if name in enabled\n'
        '    ]\n'
    )
    new = (
        '    from paradox.integrations.registry import REGISTRY\n'
        '\n'
        '    enabled = set(config.enrichment_enabled_providers)\n'
        '    # v1.1: предупреждаем об опечатках в именах провайдеров.\n'
        '    # Config — чистый dataclass, не должен знать про REGISTRY;\n'
        '    # имя провайдера — контракт integration-слоя, не Config.\n'
        '    known = set(REGISTRY)\n'
        '    unknown = enabled - known\n'
        '    if unknown:\n'
        '        import logging\n'
        '        logging.getLogger(__name__).warning(\n'
        '            "enrichment_enabled_providers: неизвестные: %s. "\n'
        '            "Известные: %s",\n'
        '            sorted(unknown), sorted(known),\n'
        '        )\n'
        '\n'
        '    providers = [\n'
        '        cls() for name, cls in REGISTRY.items() if name in enabled\n'
        '    ]\n'
    )
    return _patch(path, old, new, "pipeline: warn unknown providers")


def main():
    print("=" * 60)
    print(" fix v1.1 test failures")
    print("=" * 60)
    ok = True
    for fn in (
        revert_config_validate,
        fix_reassembler_stats,
        add_orchestrator_warning,
    ):
        try:
            if not fn():
                ok = False
        except Exception as e:
            print(f"[ERROR] {fn.__name__}: {e}", file=sys.stderr)
            ok = False
    print("\n" + "=" * 60)
    print(" DONE" if ok else " FAILED")
    print("=" * 60)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
