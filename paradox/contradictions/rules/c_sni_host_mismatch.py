"""
Правило sni_host_mismatch (domain fronting).

Случай: на одном TLS-соединении SNI в ClientHello не совпадает
с HTTP Host в запросе. Классика для обхода блокировок и C2 через
CDN: клиент говорит «я иду на cdn.legit.com» (SNI), а внутри
запроса просит attacker.com (Host).

Норма:
  - SNI = Host — обычный HTTPS.
  - SNI и Host различаются на уровне поддомена одной базовой
    организации (www.example.com vs example.com, api.example.com
    vs example.com) — норма для CDN.
  - SNI = CDN edge (cloudfront.net, akamai.net) — отфильтровано
    в facts.py по config.beaconing_allowlist_suffixes.
  - DoH / OCSP — отфильтровано по config.sni_mismatch_allowlist.

Не норма:
  - SNI = example.com, Host = attacker.com — разные SLD.

Severity: high. Не critical — есть легитимные кейсы (некоторые
корпоративные прокси, антивирусные MITM-прокси), но требует
проверки. Multiple mismatches в один SNI → эскалация (TODO).

Confidence = min(sni_conf, host_conf) × 0.9. Множитель 0.9 — за
эвристику (могли не заметить pipelined HTTP/2 с разными Hosts).
"""
from __future__ import annotations

from collections import defaultdict

from paradox.config import Config
from paradox.contradictions.base import Contradiction, Fact
from paradox.models import CaptureState, Finding

_CONF_MULTIPLIER = 0.9


class SniHostMismatchRule:
    name = "sni_host_mismatch"
    severity_base = "high"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        from paradox.contradictions.facts import extract_tls_host_facts
        return extract_tls_host_facts(state, config)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        # Группировка: (src_ip, dst_ip, dst_port) → {sni: [...], http_host: [...]}
        groups: dict[
            tuple[str, str, int | None],
            dict[str, list[Fact]],
        ] = defaultdict(lambda: {"sni": [], "http_host": []})

        for f in facts:
            if f.predicate not in ("sni", "http_host"):
                continue
            dst_ip = f.evidence.get("dst_ip")
            if not dst_ip:
                continue
            dst_port = f.evidence.get("dst_port")
            key = (f.subject, dst_ip, dst_port)
            groups[key][f.predicate].append(f)

        out: list[Contradiction] = []
        for (src, dst, dport), bucket in groups.items():
            if not bucket["sni"] or not bucket["http_host"]:
                continue

            unique_snis = {f.value for f in bucket["sni"]}
            unique_hosts = {f.value for f in bucket["http_host"]}

            # Multi-tenant HTTP/2 через CDN: разные Hosts на одном
            # TLS-соединении. Не mismatch, а design.
            if len(unique_snis) != 1 or len(unique_hosts) != 1:
                continue

            sni_fact = bucket["sni"][0]
            host_fact = bucket["http_host"][0]
            sni = sni_fact.value
            host = host_fact.value

            if sni == host:
                continue

            # Одна организация — норм (поддомены, регион, api).
            # _base_domain определён в facts.py — импорт локальный.
            from paradox.contradictions.facts import _base_domain
            if _base_domain(sni) == _base_domain(host):
                continue

            conf = round(
                min(sni_fact.confidence, host_fact.confidence)
                * _CONF_MULTIPLIER,
                3,
            )

            port_str = f":{dport}" if dport else ""
            hint = (
                f"SNI=`{sni}` ≠ HTTP Host=`{host}` на одном соединении "
                f"{src} → {dst}{port_str}. Domain fronting / VPN / "
                f"корпоративный MITM-прокси — проверить назначение "
                f"соединения и ASN получателя."
            )

            out.append(Contradiction(
                rule=self.name,
                subject=src,
                facts=[sni_fact, host_fact],
                severity=self.severity_base,
                confidence=conf,
                likely_causes=[
                    "Domain fronting: C2 или VPN-клиент прячется за "
                    "легитимным CDN через несовпадающий Host",
                    "Корпоративный MITM-прокси: переподпись сертификата, "
                    "SNI сохраняется, Host меняется",
                    "Легитимный multi-tenant CDN с нетривиальной "
                    "конфигурацией (CloudFront, Fastly)",
                    "FP парсера HTTP: Host захвачен не с этого flow",
                ],
                resolution_hint=hint,
            ))

        return out