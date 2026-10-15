"""
Правило dns_answer_mismatch (SNI ≠ резолвнутый IP).

Случай: SNI=D, DNS для D был, но клиент пришёл на dst_ip, который
НЕ входит в набор IP, резолвнутых для D (с учётом CNAME-цепочки).

Что это может быть:
  - DNS rebinding: злоумышленник меняет A-запись между резолвом
    и подключением
  - MITM-прокси: подмена dst_ip на лету, SNI остаётся валидным
  - Round-robin CDN: клиент резолвил один edge-IP, пришёл на другой.
    Митигируется allowlist CDN в extract_tls_host_facts.
  - Hardcoded IP с валидным SNI: клиент резолвит D для вида,
    ходит на заранее известный IP

Отличие от sni_without_dns:
  - sni_without_dns: DNS-ответа для D НЕТ вообще
  - dns_answer_mismatch: DNS-ответ есть, но dst_ip не из набора

Severity: medium. Confidence = 0.65 — эвристика, FP на CDN без
allowlist-суффикса и на легитимном round-robin.
"""
from __future__ import annotations

from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.base import Contradiction, Fact


class DnsAnswerMismatchRule:
    name = "dns_answer_mismatch"
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
        # Группировка (src, sni) → список фактов.
        # Один SNI, много flow → все должны попасть на резолвнутые IP.
        groups: dict[tuple[str, str], list[Fact]] = defaultdict(list)
        for f in facts:
            if f.source == "sni" and f.predicate == "sni":
                if f.evidence.get("resolved", False):
                    groups[(f.subject, f.value)].append(f)

        out: list[Contradiction] = []
        for (src, sni), group in groups.items():
            # Общий набор resolved_ips для этого SNI.
            resolved_ips: set[str] = set()
            for f in group:
                resolved_ips |= set(f.evidence.get("resolved_ips", []))

            if not resolved_ips:
                # DNS-ответ был, но без терминального A — либо CNAME
                # без A-записи, либо частичный захват. Пропускаем.
                continue

            # Факты, где dst_ip НЕ входит в resolved_ips.
            mismatched: list[Fact] = [
                f for f in group
                if f.evidence.get("dst_ip") not in resolved_ips
            ]
            if not mismatched:
                continue

            # Дедупликация по dst_ip.
            seen_dst: set[str] = set()
            uniq: list[Fact] = []
            for f in mismatched:
                dst = f.evidence.get("dst_ip", "")
                if dst and dst not in seen_dst:
                    seen_dst.add(dst)
                    uniq.append(f)

            resolved_list = sorted(resolved_ips)[:5]
            mismatched_list = sorted(seen_dst)[:5]

            hint = (
                f"{src}: SNI={sni}, но подключение на IP "
                f"{mismatched_list} не входит в резолвнутый набор "
                f"{resolved_list}. Проверить DNS rebinding / MITM "
                f"/ hardcoded IP с валидным SNI."
            )

            out.append(Contradiction(
                rule=self.name,
                subject=src,
                facts=uniq[:5],
                severity=self.severity_base,
                confidence=0.65,
                likely_causes=[
                    "DNS rebinding: A-запись изменена между "
                    "резолвом и подключением",
                    "MITM-прокси: dst_ip подменён на лету",
                    "Round-robin CDN: клиент резолвил один edge-IP, "
                    "пришёл на другой",
                    "Hardcoded IP с валидным SNI для вида",
                ],
                resolution_hint=hint,
            ))

        return out
