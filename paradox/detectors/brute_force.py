"""
BruteForceDetector — поиск перебора к одной паре dst_ip:dst_port.

Сигнал: много коротких flows с одного src_ip к одной цели.

Не путать с:
  - port scan       → много dst_port, по 1-3 пакета
  - длинной сессией → 1 flow, много пакетов
  - обычным HTTP    → flows распределены по времени, разных dst
  - трафиком к DC   → LDAP/Kerberos/SMB — это норма
  - Google Safe Browsing → много flows с разными URI
  - браузером к CDN → массовые TCP-соединения на 443

Логика:
  1. Группируем flows по (src_ip, dst_ip, dst_port).
  2. Отсеиваем DC-порты (LDAP/Kerberos/SMB).
  3. Отсеиваем TLS-порты (443/8443) — браузер к CDN, не подбор.
  4. Считаем: flow_count, unique_src_ports, avg_packets,
     уникальные URI после нормализации (strip query string).
  5. Отсеиваем по ratio unique_uris / flow_count (много разных
     URI = нормальная работа, не подбор).
  6. Отсеиваем по rate: слишком редко → поллинг.
  7. Отсеиваем по login-hint: HTTP-трафик без login endpoint
     в URI — браузер качает картинки, не подбор.
  8. Пороги: count >= min_flows, avg_packets <= max_avg,
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

from paradox.config import Config
from paradox.models import CaptureState, Finding


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
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


def _normalize_uri(uri: str | None) -> str | None:
    """Срезать query string для сравнения endpoint'ов."""
    if not uri:
        return None
    if "?" in uri:
        uri = uri.split("?", 1)[0]
    return uri or None


class BruteForceDetector:
    name = "brute_force"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        excluded_ports = config.brute_force_excluded_ports
        skip_tls_ports = config.brute_force_skip_tls_ports
        login_hints = config.login_endpoint_hints

        agg: dict[tuple[str, str, int], _Bucket] = defaultdict(_Bucket)

        for key, flow in state.flows.items():
            if key.dst_port is None:
                continue
            if key.proto != "tcp":
                continue
            # DC-порты: много коротких запросов к DC — норма.
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

            # --- Фильтр 1: ratio уникальных URI ---
            # Много разных URI = нормальная работа (браузер).
            unique_uris = bucket.uris
            if (unique_uris
                    and len(unique_uris) / flow_count
                    > config.brute_force_uri_ratio_threshold):
                continue

            duration = 0.0
            if bucket.first_seen is not None and bucket.last_seen is not None:
                duration = bucket.last_seen - bucket.first_seen

            # --- Фильтр 2: rate ---
            # Слишком редко = поллинг, не подбор.
            if duration > 0:
                rate = flow_count / duration
                if rate < config.brute_force_min_rate_flows_per_sec:
                    continue

            # --- Фильтр 3: TLS-порты ---
            # 443/8443 — массовые TCP-соединения = браузер к CDN.
            if dst_port in skip_tls_ports:
                continue

            # --- Фильтр 4: login endpoint в URI ---
            # Если HTTP-трафик и ни один URI не похож на login
            # endpoint — это не подбор пароля. Если URI нет совсем
            # (SSH/FTP/RDP) — фильтр не применяется.
            if unique_uris:
                has_login = any(
                    hint in uri.lower()
                    for uri in unique_uris
                    for hint in login_hints
                )
                if not has_login:
                    continue

            # --- Confidence ---
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
                    "rate_flows_per_sec": (
                        round(flow_count / duration, 6)
                        if duration > 0 else None
                    ),
                },
                first_seen=bucket.first_seen,
                last_seen=bucket.last_seen,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings