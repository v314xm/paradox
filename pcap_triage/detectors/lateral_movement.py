"""
LateralMovementDetector — признаки перемещения по внутренней сети.

Сигнал: внутренний → внутренний трафик на порты удалённого управления
(445 SMB, 135 RPC, 139 NetBIOS, 3389 RDP, 5985/5986 WinRM) ИЛИ
HTTP-запросы к /wsman, /cimv2 ИЛИ User-Agent инструментов
(WinRM, PsExec, Impacket).

Confidence:
  - 0.8 — если сработал UA-маркер или URI-маркер
  - 0.6 — если только порт, и только при >= N flows к одной паре
          (один RDP-сеанс к jump-host — норма, много flows —
          перебор/скан/латералка)

allowlist: config.lateral_movement_admin_srcs — jump-хосты, которые
ходят на эти порты как часть нормальной работы. Пусто по умолчанию.

Агрегация по (src_ip, dst_ip, dst_port). Несколько flows к одному
хосту — один finding.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


@dataclass
class _Bucket:
    flow_count: int = 0
    user_agents: set[str] = field(default_factory=set)
    uris: set[str] = field(default_factory=set)
    match_reasons: set[str] = field(default_factory=set)
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, ts: float | None) -> None:
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


def _match_ua(ua: str | None, markers: frozenset[str]) -> str | None:
    if not ua:
        return None
    ua_lc = ua.lower()
    for m in markers:
        if m.lower() in ua_lc:
            return m
    return None


def _match_uri(uri: str | None, markers: frozenset[str]) -> str | None:
    if not uri:
        return None
    uri_lc = uri.lower()
    for m in markers:
        if m.lower() in uri_lc:
            return m
    return None


class LateralMovementDetector:
    name = "lateral_movement"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        ports = config.lateral_movement_ports
        ua_markers = config.lateral_movement_ua_markers
        uri_markers = config.lateral_movement_uri_markers
        admin_srcs = config.lateral_movement_admin_srcs

        agg: dict[tuple[str, str, int], _Bucket] = defaultdict(_Bucket)

        for key, flow in state.flows.items():
            if key.dst_port is None:
                continue
            if key.dst_port not in ports:
                continue
            # src должен быть внутренним. Иначе — обычный трафик
            # из интернета на наш SMB-порт, это другой сигнал
            # (см. suspicious_port / port_scan).
            if not self._is_internal(key.src_ip, config):
                continue
            # allowlist: IP, которые легитимно ходят на эти порты
            if key.src_ip in admin_srcs:
                continue

            bucket = agg[(key.src_ip, key.dst_ip, key.dst_port)]
            bucket.flow_count += 1

            ua_hit = _match_ua(flow.http_user_agent, ua_markers)
            if ua_hit:
                bucket.user_agents.add(flow.http_user_agent)
                bucket.match_reasons.add("user_agent")

            uri_hit = _match_uri(flow.http_uri, uri_markers)
            if uri_hit:
                bucket.uris.add(flow.http_uri)
                bucket.match_reasons.add("uri")

            bucket.touch(flow.first_ts)
            bucket.touch(flow.last_ts)

        findings: list[Finding] = []
        for (src_ip, dst_ip, dst_port), bucket in agg.items():
            # Порт сам по себе флагуется только при множестве flows.
            # Один RDP-сеанс к jump-host — это норма, не finding.
            if not bucket.match_reasons:
                if bucket.flow_count < config.lateral_movement_min_flows_port_only:
                    continue
                bucket.match_reasons.add("port")

            if ("user_agent" in bucket.match_reasons
                    or "uri" in bucket.match_reasons):
                confidence = 0.8
            else:
                confidence = 0.6

            findings.append(Finding(
                type="lateral_movement",
                value=f"{src_ip} -> {dst_ip}:{dst_port}",
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_count": bucket.flow_count,
                    "match_reasons": sorted(bucket.match_reasons),
                    "user_agents": sorted(bucket.user_agents)[:5],
                    "uris": sorted(bucket.uris)[:5],
                },
                first_seen=bucket.first_seen,
                last_seen=bucket.last_seen,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings

    def _is_internal(self, ip: str, config: Config) -> bool:
        return any(ip.startswith(p) for p in config.private_networks)