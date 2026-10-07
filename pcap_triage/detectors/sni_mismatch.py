from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class SNIMismatchDetector:
    """
    TLS-соединения, чей SNI не встречался в DNS-запросах этого захвата.

    Что это означает:
    - domain fronting (SNI ≠ реальный хост);
    - DoH (DNS over HTTPS) — легитимно, но используется malware
      для обхода DNS-фильтров;
    - hardcoded IP/домен в малвари — резолвится не через локальный DNS.

    Агрегация по SNI, а не по flow: 8 соединений к одному домену —
    один finding, а не 8.

    Allowlist (DoH, OCSP) — в config.sni_mismatch_allowlist.
    """
    name = "sni_mismatch"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        queried = set(state.dns_queries.keys())
        allowlist = config.sni_mismatch_allowlist

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
            if sni in queried:
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