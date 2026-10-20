"""
FTPBruteForceDetector — перебор паролей к FTP-серверу.

Сигнал: много flows к одной паре (src_ip, dst_ip, dst_port=21) с
уникальными src_ports. Каждая попытка логина = новое TCP-соединение
(новый src_port), потом закрытие после отказа. 100+ попыток подряд —
однозначный словарный перебор.

Отличие от HTTP-brute_force:
  - HTTP-детектор рубит avg_packets > 20 (FTP-сессия = 1185 пакетов)
  - HTTP-детектор требует login-hint в URI, у FTP URI нет

Confidence:
  - 0.95 при flow_count >= 100
  - 0.85 при flow_count >= 50
  - 0.75 иначе (но >= ftp_brute_force_min_flows)
"""
from collections import defaultdict
from dataclasses import dataclass, field

from paradox.config import Config
from paradox.models import CaptureState, Finding


@dataclass
class _Bucket:
    flow_count: int = 0
    src_ports: set[int] = field(default_factory=set)
    packets_total: int = 0
    bytes_total: int = 0
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, ts: float | None) -> None:
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


class FTPBruteForceDetector:
    name = "ftp_brute_force"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        min_flows = config.ftp_brute_force_min_flows
        min_ports = config.ftp_brute_force_min_unique_src_ports

        agg: dict[tuple[str, str], _Bucket] = defaultdict(_Bucket)

        for key, flow in state.flows.items():
            if key.proto != "tcp":
                continue
            if key.dst_port != 21:
                continue

            bucket = agg[(key.src_ip, key.dst_ip)]
            bucket.flow_count += 1
            if key.src_port is not None:
                bucket.src_ports.add(key.src_port)
            bucket.packets_total += flow.packets
            bucket.bytes_total += flow.bytes_sent
            bucket.touch(flow.first_ts)
            bucket.touch(flow.last_ts)

        findings: list[Finding] = []
        for (src_ip, dst_ip), bucket in agg.items():
            if bucket.flow_count < min_flows:
                continue
            if len(bucket.src_ports) < min_ports:
                continue

            if bucket.flow_count >= 100:
                confidence = 0.95
            elif bucket.flow_count >= 50:
                confidence = 0.85
            else:
                confidence = 0.75

            findings.append(Finding(
                type="ftp_brute_force",
                value=f"{src_ip} -> {dst_ip}:21",
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": 21,
                    "flow_count": bucket.flow_count,
                    "unique_src_ports": len(bucket.src_ports),
                    "packets_total": bucket.packets_total,
                    "bytes_total": bucket.bytes_total,
                },
                first_seen=bucket.first_seen,
                last_seen=bucket.last_seen,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
