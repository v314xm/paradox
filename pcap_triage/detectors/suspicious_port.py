from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class SuspiciousPortDetector:
    """
    Соединения к внешним адресам на порты из suspicious_ports.

    Особенности:
    - игнорирует приватные назначения (10.x, 192.168.x, multicast и т.п.).
      Сигнал = «внутренний клиент стучится наружу на нестандартный порт»,
      а не любое соединение с портом из списка;
    - агрегирует все flow'ы по (dst_ip, dst_port) в один finding,
      чтобы 474 соединения к одному серверу давали одну строку отчёта,
      а не 474.
    """
    name = "suspicious_port"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        # ключ: (dst_ip, dst_port) → агрегат
        agg: dict[tuple[str, int], dict] = defaultdict(lambda: {
            "flow_count": 0,
            "src_ips": set(),
            "total_bytes": 0,
            "first_seen": None,
            "last_seen": None,
        })

        for key, flow in state.flows.items():
            if key.dst_port is None:
                continue
            if key.dst_port not in config.suspicious_ports:
                continue
            if self._is_private(key.dst_ip, config):
                continue

            bucket = agg[(key.dst_ip, key.dst_port)]
            bucket["flow_count"] += 1
            bucket["src_ips"].add(key.src_ip)
            bucket["total_bytes"] += flow.bytes_sent

            if flow.first_ts is not None:
                if bucket["first_seen"] is None or flow.first_ts < bucket["first_seen"]:
                    bucket["first_seen"] = flow.first_ts
            if flow.last_ts is not None:
                if bucket["last_seen"] is None or flow.last_ts > bucket["last_seen"]:
                    bucket["last_seen"] = flow.last_ts

        findings: list[Finding] = []
        for (dst_ip, dst_port), bucket in agg.items():
            findings.append(Finding(
                type="suspicious_port",
                value=f"{dst_ip}:{dst_port}",
                confidence=0.5,
                evidence={
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_count": bucket["flow_count"],
                    "src_ips": sorted(bucket["src_ips"]),
                    "total_bytes": bucket["total_bytes"],
                },
                first_seen=bucket["first_seen"],
                last_seen=bucket["last_seen"],
            ))

        # сортировка — для детерминизма
        findings.sort(key=lambda f: f.value)
        return findings

    def _is_private(self, ip: str, config: Config) -> bool:
        return any(ip.startswith(prefix) for prefix in config.private_networks)