"""
Правило sni_cert_mismatch: SNI ≠ CN/SAN сертификата.

MITM-прокси или подмена сертификата. Клиент думает, что идёт на
example.com, но сервер предъявил сертификат для другого домена.

Wildcard поддерживается: *.example.com matches a.example.com,
не matches a.b.example.com (по RFC 6125).

Severity: medium. Confidence 0.7 — сильный сигнал, но возможны FP
на CDN с shared-сертификатами и на легитимных прокси.
"""
from __future__ import annotations

from paradox.config import Config
from paradox.contradictions.base import Contradiction, Fact
from paradox.models import CaptureState, Finding


def _match_one(sni: str, pattern: str) -> bool:
    """SNI matches single CN/SAN entry с поддержкой wildcard."""
    sni = sni.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if not sni or not pattern:
        return False
    if pattern == sni:
        return True
    if pattern.startswith("*."):
        # wildcard: *.example.com matches a.example.com, но не a.b.example.com
        suffix = pattern[1:]  # ".example.com"
        if not sni.endswith(suffix):
            return False
        prefix = sni[: -len(suffix)]
        return "." not in prefix  # одноуровневый
    return False


def _sni_matches_cert(sni: str, cert_names: list[str]) -> bool:
    return any(_match_one(sni, p) for p in cert_names)


class SniCertMismatchRule:
    name = "sni_cert_mismatch"
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
            sni = ev.get("sni", "")
            if not sni:
                continue
            cert_names = []
            if ev.get("subject_cn"):
                cert_names.append(ev["subject_cn"])
            cert_names.extend(ev.get("san_dns", []))
            if not cert_names:
                continue
            if _sni_matches_cert(sni, cert_names):
                continue

            hint = (
                f"{f.subject}: SNI={sni}, но сертификат выдан на "
                f"CN={ev.get('subject_cn')}, "
                f"SAN={ev.get('san_dns', [])[:3]}. "
                f"Признак MITM-прокси или подмены сертификата."
            )
            out.append(Contradiction(
                rule=self.name,
                subject=f.subject,
                facts=[f],
                severity=self.severity_base,
                confidence=0.7,
                likely_causes=[
                    "MITM-прокси: подмена сертификата на лету",
                    "Domain fronting: SNI ≠ реальный хост",
                    "Shared-сертификат CDN без нужного SAN",
                    "FP: SNI и CN в разных регистрах, IDN и пр.",
                ],
                resolution_hint=hint,
            ))
        return out
