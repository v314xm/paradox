"""YARA-детектор для вырезанных файлов.

Сканирует state.carved_files правилами YARA.
Если библиотека yara-python не установлена, детектор пропускается.
"""
from __future__ import annotations

import os
import logging

from pcap_triage.models import Finding

try:
    import yara
except ImportError:
    yara = None

logger = logging.getLogger(__name__)


class YARADetector:
    name = "yara"

    def run(self, state, config) -> list[Finding]:
        if yara is None:
            logger.debug("yara-python not installed, skipping YARA scan")
            return []

        rules_path = getattr(config, "yara_rules_path", None)
        if not rules_path or not os.path.exists(rules_path):
            # Пытаемся найти rules/default.yar рядом с проектом
            default_path = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "default.yar")
            if os.path.exists(default_path):
                rules_path = default_path
            else:
                return []

        try:
            rules = yara.compile(filepath=rules_path)
        except Exception as e:
            logger.warning(f"Failed to compile YARA rules: {e}")
            return []

        findings = []
        for cf in getattr(state, "carved_files", []):
            matches_by_rule = {}

            # 1. Сканируем файл на диске (если включено сохранение)
            if cf.saved_path and os.path.exists(cf.saved_path):
                try:
                    for m in rules.match(filepath=cf.saved_path):
                        matches_by_rule[m.rule] = m
                except Exception as e:
                    logger.warning(f"YARA file match error ({cf.saved_path}): {e}")

            # 2. Сканируем первые 64 байта из памяти (fallback)
            if cf.first_bytes_hex:
                try:
                    data_bytes = bytes.fromhex(cf.first_bytes_hex)
                    for m in rules.match(data=data_bytes):
                        # Если правило уже сработало на полном файле, не дублируем
                        if m.rule not in matches_by_rule:
                            matches_by_rule[m.rule] = m
                except Exception as e:
                    logger.warning(f"YARA data match error ({cf.sha256[:8]}): {e}")

            # 3. Формируем Finding
            for rule_name, m in matches_by_rule.items():
                findings.append(Finding(
                    type="yara_match",
                    value=rule_name,
                    confidence=0.9,
                    evidence={
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "filename": cf.uri or cf.sha256[:12],
                        "sha256": cf.sha256,
                        "saved_path": cf.saved_path,
                    }
                ))
        return findings
