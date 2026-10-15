"""
Правило sni_without_dns (SNI на домен без DNS-ответа).

Случай: TLS ClientHello содержит SNI=D, но клиент в этом же
захвате не получал DNS-ответ для D (ни прямого, ни через
CNAME-цепочку). Значит — либо IP зашит в конфиг/клиент, либо
резолв был до захвата, либо подмена SNI в MITM-прокси.

Что отфильтровано ДО правила (в extract_tls_host_facts):
  - DoH/OCSP домены (sni_mismatch_allowlist)
  - CDN/analytics (beaconing_allowlist_suffixes)
  - legitimate_brand_domains (google/apple/microsoft и пр.)

Severity: medium. Confidence = 0.6 — эвристика, возможны FP
на клиентах с долгим DNS-кешем.
"""
from __future__ import annotations

from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.base import Contradiction, Fact


class SniWithoutDnsRule:
    name = "sni_without_dns"
    severity_base = "medium"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        from pcap_triage.contradictions.facts import (
            extract_tls_host_facts,
        )
        return extract_tls_host_facts(state, config)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        by_subject: dict[str, list[Fact]] = defaultdict(list)
        for f in facts:
            if f.source == "sni" and f.predicate == "sni":
                if not f.evidence.get("resolved", False):
                    by_subject[f.subject].append(f)

        out: list[Contradiction] = []
        for src, snis in by_subject.items():
            if len(snis) < 1:
                continue

            # Дедупликация по value: один домен, много flow — 1 факт.
            seen: set[str] = set()
            uniq: list[Fact] = []
            for f in snis:
                if f.value not in seen:
                    seen.add(f.value)
                    uniq.append(f)

            sample = ", ".join(f.value for f in uniq[:5])
            extra = ""
            if len(uniq) > 5:
                extra = f" (+{len(uniq) - 5})"

            dsts = sorted({
                f.evidence.get("dst_ip", "") for f in uniq
            } - {""})

            hint = (
                f"{src}: SNI на {len(uniq)} домен(ов) без DNS-ответа "
                f"в этом захвате: {sample}{extra}. "
                f"dst_ip: {dsts[:5]}. Проверить, что за клиент "
                f"ходит по hardcoded SNI или через MITM-прокси, "
                f"и есть ли DNS-запрос в соседних pcap."
            )

            out.append(Contradiction(
                rule=self.name,
                subject=src,
                facts=uniq[:5],
                severity=self.severity_base,
                confidence=0.6,
                likely_causes=[
                    "Hardcoded домен в конфиге клиента без DNS",
                    "Долгий DNS-кеш: резолв был до начала захвата",
                    "MITM-прокси с подменой SNI",
                    "FP: DNS через DoH/DoT, невидим в pcap",
                ],
                resolution_hint=hint,
            ))

        return out
