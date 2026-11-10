"""YARA-детектор для вырезанных файлов.

Сканирует state.carved_files правилами YARA. Источник правил:
config.yara_rules_path, иначе встроенные paradox/rules/default.yar.
Если библиотека yara-python не установлена, детектор пропускается.
"""
from __future__ import annotations

import importlib.resources
import logging
import os
import threading

from paradox.models import Finding

try:
    import yara
except ImportError:
    yara = None

logger = logging.getLogger(__name__)

# Компиляция правил — самая дорогая часть детектора, а файл между
# прогонами обычно тот же. Ключ — путь + mtime + размер: правку
# правил в GUI видно сразу, без перезапуска.
_RULES_CACHE: dict[tuple[str, int, int], object] = {}
_RULES_CACHE_LOCK = threading.Lock()


def _default_rules_path() -> str | None:
    """Путь к встроенным правилам (через importlib.resources, не os.path)."""
    try:
        resource = (
            importlib.resources.files("paradox")
            .joinpath("rules")
            .joinpath("default.yar")
        )
        path = str(resource)
    except Exception:
        return None
    return path if os.path.exists(path) else None


def _resolve_rules_path(config) -> str | None:
    path = getattr(config, "yara_rules_path", None)
    if path and os.path.exists(str(path)):
        return str(path)
    return _default_rules_path()


def _compile_rules(path: str):
    try:
        stat = os.stat(path)
    except OSError:
        # Путь проверили выше, но файл мог исчезнуть. Компилируем без
        # кэша — ошибку поймает вызывающий.
        return yara.compile(filepath=path)

    key = (path, stat.st_mtime_ns, stat.st_size)
    with _RULES_CACHE_LOCK:
        cached = _RULES_CACHE.get(key)
    if cached is not None:
        return cached

    rules = yara.compile(filepath=path)
    with _RULES_CACHE_LOCK:
        # Одна компиляция на файл: старые версии незачем держать вечно.
        for stale in [k for k in _RULES_CACHE if k[0] == path]:
            _RULES_CACHE.pop(stale, None)
        _RULES_CACHE[key] = rules
    return rules


class YARADetector:
    name = "yara"

    def run(self, state, config) -> list[Finding]:
        if yara is None:
            logger.debug("yara-python not installed, skipping YARA scan")
            return []

        rules_path = _resolve_rules_path(config)
        if rules_path is None:
            return []

        try:
            rules = _compile_rules(rules_path)
        except Exception as e:
            logger.warning(f"Failed to compile YARA rules: {e}")
            return []

        findings = []
        for cf in getattr(state, "carved_files", []):
            matches_by_rule = {}

            # 1. Полное тело: сначала из памяти (carve оставляет ссылку),
            #    затем сохранённый файл — там тело целиком тоже.
            body = getattr(cf, "body", None)
            scanned_full = False
            if body:
                try:
                    for m in rules.match(data=body):
                        matches_by_rule[m.rule] = m
                    scanned_full = True
                except Exception as e:
                    logger.warning(
                        f"YARA data match error ({cf.sha256[:8]}): {e}"
                    )
            elif cf.saved_path and os.path.exists(cf.saved_path):
                try:
                    for m in rules.match(filepath=cf.saved_path):
                        matches_by_rule[m.rule] = m
                    scanned_full = True
                except Exception as e:
                    logger.warning(
                        f"YARA file match error ({cf.saved_path}): {e}"
                    )

            # 2. Первые 64 байта — fallback, когда тела нет ни в памяти,
            #    ни на диске.
            if not scanned_full and cf.first_bytes_hex:
                try:
                    data_bytes = bytes.fromhex(cf.first_bytes_hex)
                    for m in rules.match(data=data_bytes):
                        # Если правило уже сработало на полном файле,
                        # не дублируем.
                        if m.rule not in matches_by_rule:
                            matches_by_rule[m.rule] = m
                except Exception as e:
                    logger.warning(
                        f"YARA data match error ({cf.sha256[:8]}): {e}"
                    )

            # 3. Формируем Finding
            for rule_name, m in matches_by_rule.items():
                findings.append(Finding(
                    type="yara_match",
                    value=rule_name,
                    confidence=0.9,
                    # cf.src_ip — сервер, отдавший payload; cf.dst_ip —
                    # клиент, который его скачал (flow ответа).
                    src_ip=cf.src_ip,
                    dst_ip=cf.dst_ip,
                    evidence={
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "filename": cf.uri or cf.sha256[:12],
                        "sha256": cf.sha256,
                        "saved_path": cf.saved_path,
                        "src_ip": cf.src_ip,
                        "dst_ip": cf.dst_ip,
                    },
                    # Единственная метка времени payload'а; без неё
                    # timeline выбрасывает YARA-находку.
                    first_seen=cf.first_ts,
                    last_seen=cf.first_ts,
                ))
        return findings
