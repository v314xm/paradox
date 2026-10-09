"""
SuspiciousPortDetector — соединения к внешним адресам на порты из
suspicious_ports.

Особенности:
- игнорирует приватные назначения (10.x, 192.168.x, multicast и т.п.).
  Сигнал = «внутренний клиент стучится наружу на нестандартный порт»,
  а не любое соединение с портом из списка;
- агрегирует все flow'ы по (dst_ip, dst_port) в один finding,
  чтобы 474 соединения к одному серверу давали одну строку отчёта,
  а не 474.

Фильтр port_scan:
- если все src_ips в finding'е — сканеры на этом порту
  (у каждого ≥ port_scan_min_distinct_dsts разных dst на этот порт),
  то finding пропускается — его покрывает PortScanDetector.
- если среди src_ips есть хоть один не-сканер, finding остаётся,
  чтобы не потерять легитимный сигнал.
"""
from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class SuspiciousPortDetector:
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

        # Для фильтра port_scan: (src_ip, dst_port) → set[dst_ip].
        # Если у пары много разных dst — это сканер, и его отдельные
        # suspicious_port findings дублируют port_scan.
        src_dst_map: dict[tuple[str, int], set[str]] = defaultdict(set)

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
                if (bucket["first_seen"] is None
                        or flow.first_ts < bucket["first_seen"]):
                    bucket["first_seen"] = flow.first_ts
            if flow.last_ts is not None:
                if (bucket["last_seen"] is None
                        or flow.last_ts > bucket["last_seen"]):
                    bucket["last_seen"] = flow.last_ts

            src_dst_map[(key.src_ip, key.dst_port)].add(key.dst_ip)

        # Пары (src_ip, dst_port), которые уже покрыты port_scan'ом.
        scan_pairs: set[tuple[str, int]] = {
            (src, port)
            for (src, port), dsts in src_dst_map.items()
            if len(dsts) >= config.port_scan_min_distinct_dsts
        }

        findings: list[Finding] = []
        for (dst_ip, dst_port), bucket in agg.items():
            srcs = bucket["src_ips"]

            # Если все src в этом finding'е — сканеры на этом порту,
            # finding дублирует port_scan. Пропускаем.
            if srcs and all(
                (s, dst_port) in scan_pairs for s in srcs
            ):
                continue

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