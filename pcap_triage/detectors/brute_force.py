"""
BruteForceDetector — поиск перебора к одной паре dst_ip:dst_port.

Сигнал: много коротких flows с одного src_ip к одной цели.
Не путать с:
  - port scan       → много dst_port, по 1-3 пакета
  - длинной сессией → 1 flow, много пакетов
  - обычным HTTP    → flows распределены по времени, разных dst

Логика:
  1. Группируем flows по (src_ip, dst_ip, dst_port).
  2. Считаем: count flows, unique src_ports, avg packets per flow.
  3. Если count >= min_flows AND avg_packets <= max_avg_packets
     AND unique_src_ports >= min_unique_src_ports
     → finding "brute_force".

Каждая попытка аутентификации = новый src_port.
Поэтому unique_src_ports ≈ count flows, и это второй независимый
признак, что идёт перебор, а не длинная сессия.
"""
from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class BruteForceDetector:
    name = "brute_force"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        # ключ: (src_ip, dst_ip, dst_port) → агрегат
        agg: dict[tuple[str, str, int], dict] = defaultdict(lambda: {
            "flow_count": 0,
            "packets_total": 0,
            "src_ports": set(),
            "bytes_total": 0,
            "first_seen": None,
            "last_seen": None,
        })

        for key, flow in state.flows.items():
            if key.dst_port is None:
                continue
            if key.proto != "tcp":
                continue

            bucket = agg[(key.src_ip, key.dst_ip, key.dst_port)]
            bucket["flow_count"] += 1
            bucket["packets_total"] += flow.packets
            bucket["bytes_total"] += flow.bytes_sent
            if key.src_port is not None:
                bucket["src_ports"].add(key.src_port)

            if flow.first_ts is not None:
                if bucket["first_seen"] is None or flow.first_ts < bucket["first_seen"]:
                    bucket["first_seen"] = flow.first_ts
            if flow.last_ts is not None:
                if bucket["last_seen"] is None or flow.last_ts > bucket["last_seen"]:
                    bucket["last_seen"] = flow.last_ts

        findings: list[Finding] = []

        for (src_ip, dst_ip, dst_port), bucket in agg.items():
            flow_count = bucket["flow_count"]
            if flow_count < config.brute_force_min_flows:
                continue

            avg_packets = bucket["packets_total"] / flow_count
            if avg_packets > config.brute_force_max_avg_packets:
                continue

            unique_src_ports = len(bucket["src_ports"])
            if unique_src_ports < config.brute_force_min_unique_src_ports:
                continue

            duration = 0.0
            if bucket["first_seen"] is not None and bucket["last_seen"] is not None:
                duration = bucket["last_seen"] - bucket["first_seen"]

            # confidence растёт с числом flows и числом уникальных портов
            # максимум 0.95
            flow_score = min(1.0, flow_count / 100.0)
            port_score = min(1.0, unique_src_ports / 50.0)
            confidence = round(0.5 + 0.3 * flow_score + 0.15 * port_score, 3)
            confidence = min(confidence, 0.95)

            findings.append(Finding(
                type="brute_force",
                value=f"{src_ip} -> {dst_ip}:{dst_port}",
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_count": flow_count,
                    "unique_src_ports": unique_src_ports,
                    "packets_total": bucket["packets_total"],
                    "bytes_total": bucket["bytes_total"],
                    "avg_packets_per_flow": round(avg_packets, 2),
                    "duration_sec": round(duration, 2),
                    "rate_flows_per_sec": round(
                        flow_count / duration, 2
                    ) if duration > 0 else None,
                },
                first_seen=bucket["first_seen"],
                last_seen=bucket["last_seen"],
            ))

        findings.sort(key=lambda f: f.value)
        return findings