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
            # По умолчанию ищем в папке rules/default.yar (если есть)
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
            # У CarvedFile данные обычно лежат в поле data или raw_bytes
            data = getattr(cf, "data", getattr(cf, "raw_bytes", getattr(cf, "content", b"")))
            if not data:
                continue

            try:
                matches = rules.match(data=data)
            except Exception as e:
                logger.warning(f"YARA match error: {e}")
                continue

            for m in matches:
                findings.append(Finding(
                    type="yara_match",
                    value=m.rule,
                    confidence=0.9,
                    evidence={
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "filename": getattr(cf, "filename", "unknown"),
                    }
                ))
        return findings
