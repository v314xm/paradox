"""
BruteForceDetector — поиск перебора к одной паре dst_ip:dst_port.

Сигнал: много коротких flows с одного src_ip к одной цели.

Не путать с:
  - port scan       → много dst_port, по 1-3 пакета
  - длинной сессией → 1 flow, много пакетов
  - обычным HTTP    → flows распределены по времени, разных dst
  - трафиком к DC   → LDAP/Kerberos/SMB — это норма
  - Google Safe Browsing → много flows с разными URI

Логика:
  1. Группируем flows по (src_ip, dst_ip, dst_port).
  2. Отсеиваем DC-порты (LDAP/Kerberos/SMB).
  3. Считаем: flow_count, unique_src_ports, avg_packets,
     уникальные URI после нормализации (strip query string).
  4. Отсеиваем, если ratio unique_uris / flow_count > порога
     (много разных URI = нормальная работа, не подбор).
  5. Пороги: count >= min_flows, avg_packets <= max_avg,
     unique_src_ports >= min_unique_src_ports.

Каждая попытка аутентификации = новый src_port.
Поэтому unique_src_ports ≈ count flows — второй независимый
признак перебора, а не длинной сессии.

Известное ограничение: SYN-скан с одного src на один dst:port
тоже похож на этот паттерн. Отличить можно только по наличию
SYN+ACK — этого сигнала в FlowStats нет. См. TODO.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


@dataclass
class _Bucket:
    """Агрегат flows для пары (src_ip, dst_ip, dst_port)."""
    flow_count: int = 0
    packets_total: int = 0
    bytes_sent_total: int = 0
    src_ports: set[int] = field(default_factory=set)
    uris: set[str] = field(default_factory=set)
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, ts: float | None) -> None:
        """Обновить first_seen / last_seen."""
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


def _normalize_uri(uri: str | None) -> str | None:
    """
    Срезать query string для сравнения endpoint'ов.

    При подборе пароля URI может быть:
      /login.php?user=admin
      /login.php?user=bob
    Это один и тот же endpoint. Без нормализации ratio
    уникальных URI завышается, и детектор пропускает подбор
    (false negative).

    Возвращает URI без query, в original case (path
    case-sensitive, не lowercase).
    """
    if not uri:
        return None
    if "?" in uri:
        uri = uri.split("?", 1)[0]
    return uri or None


class BruteForceDetector:
    name = "brute_force"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        excluded_ports = config.brute_force_excluded_ports

        agg: dict[tuple[str, str, int], _Bucket] = defaultdict(_Bucket)

        for key, flow in state.flows.items():
            if key.dst_port is None:
                continue
            if key.proto != "tcp":
                continue
            # DC-порты: много коротких запросов к DC — нормальная
            # работа инфраструктуры, не подбор пароля.
            if key.dst_port in excluded_ports:
                continue

            bucket = agg[(key.src_ip, key.dst_ip, key.dst_port)]
            bucket.flow_count += 1
            bucket.packets_total += flow.packets
            bucket.bytes_sent_total += flow.bytes_sent
            if key.src_port is not None:
                bucket.src_ports.add(key.src_port)

            uri = _normalize_uri(flow.http_uri)
            if uri:
                bucket.uris.add(uri)

            bucket.touch(flow.first_ts)
            bucket.touch(flow.last_ts)

        findings: list[Finding] = []

        for (src_ip, dst_ip, dst_port), bucket in agg.items():
            flow_count = bucket.flow_count
            if flow_count < config.brute_force_min_flows:
                continue

            avg_packets = bucket.packets_total / flow_count
            if avg_packets > config.brute_force_max_avg_packets:
                continue

            unique_src_ports = len(bucket.src_ports)
            if unique_src_ports < config.brute_force_min_unique_src_ports:
                continue

            # Отсеивание по уникальным URI: если у flow'ов пары
            # много разных URI — это не подбор пароля, а нормальная
            # работа (браузер качает объекты, Safe Browsing и т.п.).
            unique_uris = bucket.uris
            if (unique_uris
                    and len(unique_uris) / flow_count
                    > config.brute_force_uri_ratio_threshold):
                continue

            duration = 0.0
            if bucket.first_seen is not None and bucket.last_seen is not None:
                duration = bucket.last_seen - bucket.first_seen

            # Отсеивание по rate: если попытки распределены по времени
            # слишком редко — это поллинг, а не подбор пароля.
            # Firefox Safe Browsing: 29 flow'ов за 7.5 часов ≈ 0.001 flow/s.
            # Настоящий подбор: либо быстрый (>1 flow/s), либо с rate
            # limiting (≥0.01 flow/s).
            if duration > 0:
                rate = flow_count / duration
                if rate < config.brute_force_min_rate_flows_per_sec:
                    continue

            # Confidence растёт с числом flows и числом уникальных
            # src_ports. Коэффициенты подобраны эмпирически:
            # - 100+ flows → насыщение по flow_score
            # - 50+ unique src_ports → насыщение по port_score
            # Это domain logic, а не настройка — не в config.
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
                    "unique_uris": len(unique_uris),
                    "packets_total": bucket.packets_total,
                    "bytes_sent_total": bucket.bytes_sent_total,
                    "avg_packets_per_flow": round(avg_packets, 2),
                    "duration_sec": round(duration, 2),
                    # duration == 0 → все события одновременно,
                    # rate фактически бесконечный. None честнее,
                    # чем делить на ноль.
                    "rate_flows_per_sec": (
                        round(flow_count / duration, 6)
                        if duration > 0 else None
                    ),

                },
                first_seen=bucket.first_seen,
                last_seen=bucket.last_seen,
            ))

        # Сначала по убыванию confidence, потом по value —
        # важные находки выше, детерминизм сохранён.
        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings