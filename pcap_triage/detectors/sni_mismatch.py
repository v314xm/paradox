from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class SNIMismatchDetector:
    """
    TLS-соединения, чей SNI не встречался в DNS-ОТВЕТАХ этого захвата.

    Отличие от старой логики (v0.7.0): сравниваем с dns_answers_by_name
    (ответы), а не dns_queries (запросы). Что это даёт:
      - DoH: клиент спросил example.com, но ответ шёл через DoH-канал
        (в plaintext DNS не виден). Старое правило — FP, новое молчит.
      - NXDOMAIN: запрос был, ответа нет → правильно сигналим.
      - CNAME: клиент резолвил www.foo.com → cdn.foo.com. Правило
        считает cdn.foo.com резолвнутым (он в значениях), FP нет.

    Что это означает:
    - domain fronting (SNI ≠ реальный хост);
    - hardcoded IP/домен в малвари — резолвится не через локальный DNS;
    - клиент с долгим DNS-кешем (резолв был до захвата).

    Агрегация по SNI, а не по flow: 8 соединений к одному домену —
    один finding, а не 8.

    Allowlist: sni_mismatch_allowlist (DoH/OCSP) +
    legitimate_brand_domains (google/microsoft/apple и пр.).
    """
    name = "sni_mismatch"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        # Резолв по ОТВЕТАМ, не по запросам. См. docstring.
        # resolved_names — ключи (прямой A-запрос для этого имени).
        # resolved_values — значения (CNAME-таргеты в цепочке).
        resolved_names = set(state.dns_answers_by_name.keys())
        resolved_values: set[str] = set()
        for ips in state.dns_answers_by_name.values():
            resolved_values |= ips

        # Три набора, согласовано с extract_tls_host_facts
        # (правило SniWithoutDnsRule использует те же самые):
        #   - sni_mismatch_allowlist: DoH, OCSP, CRL
        #   - legitimate_brand_domains: google/apple/microsoft/twitter
        #   - beaconing_allowlist_suffixes: CDN (akamai, cloudflare и пр.)
        allowlist = (
            config.sni_mismatch_allowlist
            | config.legitimate_brand_domains
            | config.beaconing_allowlist_suffixes
        )

        # SNI → агрегат
        agg: dict[str, dict] = defaultdict(lambda: {
            "flow_count": 0,
            "dst_ips": set(),
            "dst_ports": set(),
            "total_bytes": 0,
            "first_seen": None,
            "last_seen": None,
        })

        for key, flow in state.flows.items():
            sni = flow.sni
            if not sni:
                continue
            if sni in resolved_names or sni in resolved_values:
                continue
            if self._in_allowlist(sni, allowlist):
                continue

            bucket = agg[sni]
            bucket["flow_count"] += 1
            bucket["dst_ips"].add(key.dst_ip)
            if key.dst_port is not None:
                bucket["dst_ports"].add(key.dst_port)
            bucket["total_bytes"] += flow.bytes_sent

            if flow.first_ts is not None:
                if bucket["first_seen"] is None or flow.first_ts < bucket["first_seen"]:
                    bucket["first_seen"] = flow.first_ts
            if flow.last_ts is not None:
                if bucket["last_seen"] is None or flow.last_ts > bucket["last_seen"]:
                    bucket["last_seen"] = flow.last_ts

        findings: list[Finding] = []
        for sni, bucket in agg.items():
            if bucket["flow_count"] < config.sni_mismatch_min_flows:
                continue

            findings.append(Finding(
                type="sni_without_dns",
                value=sni,
                confidence=0.6,
                evidence={
                    "sni": sni,
                    "flow_count": bucket["flow_count"],
                    "dst_ips": sorted(bucket["dst_ips"]),
                    "dst_ports": sorted(bucket["dst_ports"]),
                    "total_bytes": bucket["total_bytes"],
                },
                first_seen=bucket["first_seen"],
                last_seen=bucket["last_seen"],
            ))

        findings.sort(key=lambda f: f.value)
        return findings

    def _in_allowlist(self, sni: str, allowlist: set[str]) -> bool:
        """Проверка на вхождение в allowlist по суффиксу.

        `smartscreen.microsoft.com` покрывает и
        `nav-edge.smartscreen.microsoft.com`. Точное совпадение — тоже
        срабатывает.
        """
        for entry in allowlist:
            if sni == entry or sni.endswith("." + entry):
                return True
        return False