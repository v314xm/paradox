"""
Правило self_signed_cert: сертификат самоподписанный.

issuer == subject. В интернете для публичных сервисов — аномалия:
нормальные сервисы используют Let's Encrypt / DigiCert / и т.п.

Ограничение: правило смотрит только на external dst (внутренние
self-signed — норма: dev-серверы, IoT, тестовые стенды).

Severity: medium. Confidence 0.7 — сильный сигнал, но FP на
pin-сертификатах (pin-сертификаты часто self-signed) и легитимных
dev-стендах наружу.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.models import CaptureState, Finding
from paradox.contradictions.base import Contradiction, Fact


class SelfSignedCertRule:
    name = "self_signed_cert"
    severity_base = "medium"

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
            if not ev.get("is_self_signed"):
                continue

            subject_cn = ev.get("subject_cn") or "?"
            hint = (
                f"{f.subject} → {ev.get('dst_ip')}:{ev.get('dst_port')}: "
                f"self-signed сертификат (CN={subject_cn}). "
                f"Для публичного сервиса — аномалия; проверить, "
                f"не MITM-прокси и не dev-стенд."
            )
            out.append(Contradiction(
                rule=self.name,
                subject=f.subject,
                facts=[f],
                severity=self.severity_base,
                confidence=0.7,
                likely_causes=[
                    "MITM-прокси с самоподписанным сертификатом",
                    "Dev-стенд или IoT-устройство, случайно доступное наружу",
                    "Certificate pinning: pin-сертификат часто self-signed",
                    "Легитимный внутренний сервис с публичным DNS",
                ],
                resolution_hint=hint,
            ))
        return out
