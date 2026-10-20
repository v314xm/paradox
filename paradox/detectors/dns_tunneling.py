"""
DNSTunnelingDetector — DNS-туннелирование (exfiltration через DNS).

Признак: длинные уникальные поддомены под одним базовым доменом
от одного клиента. Данные кодируются в qname (base64, hex, custom).

Пример:
  aGVsbG8gd29ybGQ.dns.attacker.com
  d29ybGQgaGVsbG8.dns.attacker.com
  ...

Отличие от DGA:
  - DGA — короткие поддомены (10-15 символов), много разных
  - Tunneling — длинные поддомены (>50), тоже много
Требуем min_qname_length, чтобы DGA не сработал как tunneling.

Отличие от cloud_tunnel_domain:
  - cloud_tunnel_domain — известные сервисы (trycloudflare, ngrok)
  - DNS tunneling — самодельный протокол через DNS

Confidence: 0.9 при длинных qname + много запросов, 0.7 иначе.
"""
from collections import defaultdict

from paradox.config import Config
from paradox.models import CaptureState, Finding


def _extract_base_domain(qname: str) -> str:
    """v0.9.0: учитывает двухуровневые TLD (co.uk, com.au)."""
    from paradox.domain_utils import base_domain
    return base_domain(qname)


class DNSTunnelingDetector:
    name = "dns_tunneling"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        min_len = config.dns_tunneling_min_qname_length
        min_long = config.dns_tunneling_min_long_qnames
        min_queries = config.dns_tunneling_min_queries
        allowlist = config.dns_tunneling_allowlist

        findings: list[Finding] = []

        # Группируем по (src_ip, base_domain)
        # value: set[qname] и total_queries
        groups: dict[tuple[str, str], dict] = defaultdict(
            lambda: {"qnames": set(), "total_queries": 0, "long_qnames": set()}
        )

        for src_ip, queries in state.dns_queries_by_src.items():
            for qname, count in queries.items():
                qname_lc = qname.lower().strip(".")
                if not qname_lc:
                    continue
                base = _extract_base_domain(qname_lc)

                # Allowlist (DoH и пр.) — пропускаем
                if any(
                    qname_lc == a or qname_lc.endswith("." + a)
                    for a in allowlist
                ):
                    continue

                key = (src_ip, base)
                groups[key]["qnames"].add(qname_lc)
                groups[key]["total_queries"] += count
                if len(qname_lc) >= min_len:
                    groups[key]["long_qnames"].add(qname_lc)

        for (src_ip, base), data in groups.items():
            if data["total_queries"] < min_queries:
                continue
            if len(data["long_qnames"]) < min_long:
                continue

            long_count = len(data["long_qnames"])
            total_unique = len(data["qnames"])

            confidence = 0.9 if long_count >= min_long * 2 else 0.7

            # Сэмпл длинных qname (первые 5 по алфавиту)
            samples = sorted(data["long_qnames"])[:5]

            findings.append(Finding(
                type="dns_tunneling",
                value=f"{src_ip} -> {base}",
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "base_domain": base,
                    "total_queries": data["total_queries"],
                    "unique_qnames": total_unique,
                    "long_qnames_count": long_count,
                    "min_qname_length": min_len,
                    "samples": samples,
                },
                first_seen=None,
                last_seen=None,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
