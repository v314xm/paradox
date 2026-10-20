"""
Правило expired_cert: сертификат был просрочен во время соединения.

not_after < first_ts flow. Означает: клиент соединился с сервером,
чей сертификат уже истёк. Нормальные браузеры такое блокируют.
Если соединение состоялось — это либо старый клиент без проверки,
либо MITM, либо ошибка конфигурации.

Severity: low. Confidence 0.9 — факт точный, но само по себе
не критично (не атака).
"""
from __future__ import annotations

from datetime import UTC

from paradox.config import Config
from paradox.contradictions.base import Contradiction, Fact
from paradox.models import CaptureState, Finding


class ExpiredCertRule:
    name = "expired_cert"
    severity_base = "low"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        from paradox.contradictions.facts import extract_tls_cert_facts
        return extract_tls_cert_facts(state)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        out: list[Contradiction] = []
        for f in facts:
            ev = f.evidence
            not_after_ts = ev.get("not_after_ts", 0.0)
            if not not_after_ts or not f.ts:
                continue
            if not_after_ts >= f.ts:
                continue

            from datetime import datetime
            try:
                expires_iso = datetime.fromtimestamp(
                    not_after_ts, tz=UTC,
                ).strftime("%Y-%m-%d %H:%M")
                seen_iso = datetime.fromtimestamp(
                    f.ts, tz=UTC,
                ).strftime("%Y-%m-%d %H:%M")
            except (OSError, ValueError):
                expires_iso, seen_iso = "?", "?"

            hint = (
                f"{f.subject} → {ev.get('dst_ip')}:{ev.get('dst_port')}: "
                f"сертификат истёк {expires_iso}, но соединение "
                f"состоялось {seen_iso}. "
                f"Клиент без проверки срока, MITM или ошибка конфигурации."
            )
            out.append(Contradiction(
                rule=self.name,
                subject=f.subject,
                facts=[f],
                severity=self.severity_base,
                confidence=0.9,
                likely_causes=[
                    "Старый клиент без проверки срока действия",
                    "MITM-прокси со старым сертификатом",
                    "Ошибка конфигурации сервера",
                ],
                resolution_hint=hint,
            ))
        return out
