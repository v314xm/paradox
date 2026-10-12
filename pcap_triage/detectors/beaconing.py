"""
BeaconingDetector — периодические обращения к C2 (heartbeat).

Признак: множество TCP-соединений к одной паре (src_ip, dst_ip, dst_port)
с регулярным интервалом. C2-heartbeat — запрограммированный таймер
с малым jitter.

Пример: заражённый хост каждые 60 секунд (±5) стучится на C2. Соединения
короткие (heartbeat), но регулярные.

Логика:
- Группировка FlowKey по (src_ip, dst_ip, dst_port) — src_port не важен,
  потому что каждый beacon = новое TCP-соединение с новым src_port.
- N >= beaconing_min_connections (10).
- Длительность >= beaconing_min_duration_sec (300).
- jitter = stddev(intervals) / mean(intervals) < beaconing_max_jitter_ratio (0.2).
- Средний размер flow < beaconing_max_avg_bytes (5000).

Confidence: 0.85 при jitter 0.05, 0.6 при jitter = max_jitter_ratio.

Отличие от brute_force:
  - brute_force — много flows к одной цели ЗА КОРОТКОЕ ВРЕМЯ.
  - beaconing   — много flows к одной цели с РАВНЫМИ ИНТЕРВАЛАМИ
                  на длинном горизонте.

Отличие от port_scan:
  - port_scan — много разных dst на один порт.
  - beaconing — много flows к ОДНОЙ паре (dst_ip, dst_port).
"""
import statistics
from collections import defaultdict
from dataclasses import dataclass, field

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


@dataclass
class _BeaconGroup:
    first_timestamps: list[float] = field(default_factory=list)
    total_bytes: int = 0
    total_packets: int = 0
    count: int = 0

    @property
    def duration(self) -> float:
        if len(self.first_timestamps) < 2:
            return 0.0
        return max(self.first_timestamps) - min(self.first_timestamps)

    def avg_bytes(self) -> float:
        if self.count == 0:
            return 0.0
        return self.total_bytes / self.count


class BeaconingDetector:
    name = "beaconing"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        min_conn = config.beaconing_min_connections
        min_duration = config.beaconing_min_duration_sec
        max_jitter = config.beaconing_max_jitter_ratio
        max_avg_bytes = config.beaconing_max_avg_bytes

        groups: dict[tuple[str, str, int], _BeaconGroup] = defaultdict(
            _BeaconGroup
        )

        for key, flow in state.flows.items():
            if key.proto != "tcp":
                continue
            if key.dst_port is None:
                continue
            if flow.first_ts is None:
                continue

            group = groups[(key.src_ip, key.dst_ip, key.dst_port)]
            group.first_timestamps.append(flow.first_ts)
            group.total_bytes += flow.bytes_sent
            group.total_packets += flow.packets
            group.count += 1

        findings: list[Finding] = []
        for (src_ip, dst_ip, dst_port), g in groups.items():
            if g.count < min_conn:
                continue
            if g.duration < min_duration:
                continue

            ts_sorted = sorted(g.first_timestamps)
            intervals = [
                ts_sorted[i + 1] - ts_sorted[i]
                for i in range(len(ts_sorted) - 1)
            ]
            intervals = [iv for iv in intervals if iv > 0]
            if len(intervals) < min_conn - 1:
                continue

            mean_iv = statistics.mean(intervals)
            if mean_iv <= 0:
                continue
            stdev_iv = statistics.pstdev(intervals)
            jitter = stdev_iv / mean_iv

            if jitter >= max_jitter:
                continue

            avg_bytes = g.avg_bytes()
            if avg_bytes > max_avg_bytes:
                continue

            # Confidence: 0.85 при jitter→0, 0.6 при jitter→max_jitter
            confidence = 0.6 + 0.25 * (1 - jitter / max_jitter)
            confidence = max(0.6, min(0.85, confidence))

            findings.append(Finding(
                type="beaconing",
                value=f"{src_ip} -> {dst_ip}:{dst_port}",
                confidence=round(confidence, 3),
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "count": g.count,
                    "duration_sec": round(g.duration, 1),
                    "mean_interval_sec": round(mean_iv, 2),
                    "stdev_interval_sec": round(stdev_iv, 3),
                    "jitter_ratio": round(jitter, 3),
                    "avg_bytes_per_conn": round(avg_bytes, 1),
                    "total_bytes": g.total_bytes,
                    "total_packets": g.total_packets,
                },
                first_seen=ts_sorted[0],
                last_seen=ts_sorted[-1],
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings