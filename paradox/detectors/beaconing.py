"""
BeaconingDetector — периодические обращения к C2 (heartbeat).

Признак: множество TCP-соединений к одной паре (src_ip, dst_ip, dst_port)
с регулярным интервалом. C2-heartbeat — запрограммированный таймер
с малым jitter.

Пример: заражённый хост каждые 60 секунд (±2) стучится на C2.
Соединения короткие (heartbeat), но регулярные.

Логика (0.7.0):
- Группировка FlowKey по (src_ip, dst_ip, dst_port).
- N >= beaconing_min_connections (20).
- Длительность >= beaconing_min_duration_sec (600).
- jitter = stddev(intervals) / mean(intervals) < 0.1.
- Средний размер flow < beaconing_max_avg_bytes (5000).
- Rate = count / duration_min <= beaconing_max_flows_per_minute (5).
- stddev(payload)/mean(payload) <= beaconing_payload_stddev_ratio_max (0.5).
- dst_ip не internal (по флагу beaconing_skip_internal_dst).
- dst_port не в mail-портах (POP3/IMAP).
- Группа не multi-tenant: <= 1 уникального SNI/Host.
- Единственный SNI/Host не в allowlist.

Что отсеивается:
- Mail polling (POP3/IMAP) — порт-фильтр.
- Chrome keepalive к CDN/analytics — multi-tenant filter +
  SNI/Host allowlist.
- Windows Update, Apple CDN — SNI/Host allowlist.
- Burst-соединения (Chrome parallel fetch) — rate check.
- Browser keepalive с разным payload — payload variance.

Что остаётся:
- C2 на одном домене/IP: один SNI (или нет SNI), const payload,
  низкий jitter, долгий горизонт.

Confidence: 0.85 при jitter → 0, 0.6 при jitter → max_jitter_ratio.

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

from paradox.config import Config
from paradox.models import CaptureState, Finding
from paradox.net_utils import is_internal_ip


@dataclass
class _BeaconGroup:
    first_timestamps: list[float] = field(default_factory=list)
    per_flow_bytes: list[int] = field(default_factory=list)
    sni_set: set[str] = field(default_factory=set)
    host_set: set[str] = field(default_factory=set)
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

    def payload_stddev_ratio(self) -> float | None:
        """
        stddev/mean по размеру payload.

        C2: const payload → 0.0.
        Browser: разные запросы → > 0.5.

        Возвращает None, если данных < 5 flow.
        """
        if len(self.per_flow_bytes) < 5:
            return None
        mean = statistics.mean(self.per_flow_bytes)
        if mean <= 0:
            return None
        return statistics.pstdev(self.per_flow_bytes) / mean

    def unique_destinations(self) -> set[str]:
        """
        Уникальные SNI + HTTP Host в группе.

        0 — нет ни SNI, ни Host (raw IP, возможно C2).
        1 — один домен (C2 ИЛИ однодоменный сервис).
        >1 — shared CDN/edge (Chrome к Akamai, multi-tenant edge).
        """
        return self.sni_set | self.host_set


def _suffix_match(value: str, suffixes: frozenset[str]) -> bool:
    """
    endswith-проверка по доменному суффиксу.

    'www.google-analytics.com' matches 'google-analytics.com'.
    'notgoogle-analytics.com' does NOT match (нужна точка перед).
    """
    if not value:
        return False
    v = value.lower().rstrip(".")
    return any(v == s or v.endswith("." + s) for s in suffixes)


class BeaconingDetector:
    name = "beaconing"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        min_conn = config.beaconing_min_connections
        min_duration = config.beaconing_min_duration_sec
        max_jitter = config.beaconing_max_jitter_ratio
        max_avg_bytes = config.beaconing_max_avg_bytes
        max_rate = config.beaconing_max_flows_per_minute
        max_payload_var = config.beaconing_payload_stddev_ratio_max
        skip_internal = config.beaconing_skip_internal_dst
        mail_ports = config.beaconing_mail_polling_ports
        allow_suffixes = config.beaconing_allowlist_suffixes
        allow_ips = config.beaconing_allowlist_ips

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

            # Mail-порты: POP3/IMAP поллинг = design, не C2.
            # SMTP (25/465/587) НЕ здесь — бывает C2-канал.
            if key.dst_port in mail_ports:
                continue

            # Точечный IP allowlist (analytics без SNI).
            if key.dst_ip in allow_ips:
                continue

            # internal → internal — отдельная история.
            if skip_internal and is_internal_ip(key.dst_ip, config):
                continue

            group = groups[(key.src_ip, key.dst_ip, key.dst_port)]
            group.first_timestamps.append(flow.first_ts)
            group.per_flow_bytes.append(flow.bytes_sent)
            group.total_bytes += flow.bytes_sent
            group.total_packets += flow.packets
            group.count += 1
            if flow.sni:
                group.sni_set.add(flow.sni.lower())
            if flow.http_host:
                group.host_set.add(flow.http_host.lower())

        findings: list[Finding] = []
        for (src_ip, dst_ip, dst_port), g in groups.items():
            if g.count < min_conn:
                continue
            if g.duration < min_duration:
                continue

            # Multi-tenant filter: > 1 уникального SNI/Host = shared edge.
            # Chrome к Akamai открывает десятки соединений к одному IP,
            # но каждый — с разным SNI. C2 использует ОДИН домен.
            unique_dests = g.unique_destinations()
            if len(unique_dests) > 1:
                continue

            # SNI/Host allowlist: один dest, но известный CDN/analytics.
            if len(unique_dests) == 1 and allow_suffixes:
                (single_dest,) = unique_dests
                if _suffix_match(single_dest, allow_suffixes):
                    continue

            # Rate check: Chrome параллельно открывает пачку.
            duration_min = g.duration / 60.0
            if duration_min <= 0:
                continue
            flow_rate = g.count / duration_min
            if flow_rate > max_rate:
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

            payload_var = g.payload_stddev_ratio()
            if payload_var is not None and payload_var > max_payload_var:
                continue

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
                    "flow_rate_per_min": round(flow_rate, 2),
                    "mean_interval_sec": round(mean_iv, 2),
                    "stdev_interval_sec": round(stdev_iv, 3),
                    "jitter_ratio": round(jitter, 3),
                    "avg_bytes_per_conn": round(avg_bytes, 1),
                    "payload_stddev_ratio": (
                        round(payload_var, 3)
                        if payload_var is not None
                        else None
                    ),
                    "unique_destinations": sorted(unique_dests),
                    "total_bytes": g.total_bytes,
                    "total_packets": g.total_packets,
                },
                first_seen=ts_sorted[0],
                last_seen=ts_sorted[-1],
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
