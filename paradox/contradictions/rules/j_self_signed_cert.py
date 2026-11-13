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
from paradox.contradictions.base import Contradiction, Fact
from paradox.i18n import L
from paradox.models import CaptureState, Finding


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
        from paradox.net_utils import is_internal_ip
        # Фильтр external dst — как обещано в докстринге выше.
        # Внутренние self-signed (dev-стенды, IoT, тестовые стенды) —
        # норма, и раньше каждый такой хост давал contradiction.
        return [
            f for f in extract_tls_cert_facts(state)
            if not is_internal_ip(f.evidence.get("dst_ip", ""), config)
        ]

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        out: list[Contradiction] = []
        for f in facts:
            ev = f.evidence
            if not ev.get("is_self_signed"):
                continue

            subject_cn = ev.get("subject_cn") or "?"
            hint = L(
                (
                    f"{f.subject} → {ev.get('dst_ip')}:{ev.get('dst_port')}: "
                    f"self-signed сертификат (CN={subject_cn}). "
                    f"Для публичного сервиса — аномалия; проверить, "
                    f"не MITM-прокси и не dev-стенд."
                ),
                (
                    f"{f.subject} → {ev.get('dst_ip')}:{ev.get('dst_port')}: "
                    f"self-signed certificate (CN={subject_cn}). "
                    f"An anomaly for a public service; check that it is "
                    f"neither an MITM proxy nor a dev stand."
                ),
            )
            out.append(Contradiction(
                rule=self.name,
                subject=f.subject,
                facts=[f],
                severity=self.severity_base,
                confidence=0.7,
                likely_causes=[
                    L(
                        "MITM-прокси с самоподписанным сертификатом",
                        "MITM proxy with a self-signed certificate",
                    ),
                    L(
                        "Dev-стенд или IoT-устройство, случайно доступное "
                        "наружу",
                        "Dev stand or IoT device accidentally exposed to "
                        "the internet",
                    ),
                    L(
                        "Certificate pinning: pin-сертификат часто self-signed",
                        "Certificate pinning: the pinned certificate is often "
                        "self-signed",
                    ),
                    L(
                        "Легитимный внутренний сервис с публичным DNS",
                        "Legitimate internal service with a public DNS name",
                    ),
                ],
                resolution_hint=hint,
            ))
        return out
