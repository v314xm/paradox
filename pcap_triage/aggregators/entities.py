"""
Агрегация flows и findings в сущности (хосты).

Один IP = одна Entity. Вместо 500 flow-строк — 20-50 сущностей
с ролью и статистикой.

Роли:
  internal / external        — базовая классификация
  gateway_candidate          — internal с большим числом исходящих
  victim_candidate           — internal с findings
  c2_candidate               — external с findings
"""
from dataclasses import dataclass, field
from ipaddress import ip_address

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.net_utils import is_internal_ip


@dataclass
class Entity:
    ip: str
    is_internal: bool
    roles: list[str] = field(default_factory=list)

    first_seen: float | None = None
    last_seen: float | None = None

    flows_out: int = 0
    flows_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0

    unique_dsts: set[str] = field(default_factory=set)
    unique_srcs: set[str] = field(default_factory=set)

    sni_domains: set[str] = field(default_factory=set)
    dns_names: set[str] = field(default_factory=set)

    findings_indices: list[int] = field(default_factory=list)

    # --- зарезервировано под будущие экстракторы ---
    mac: str | None = None
    hostname: str | None = None
    username: str | None = None
    asn: str | None = None
    country: str | None = None

    def to_dict(self) -> dict:
        """Сериализация для JSON. Sets превращаем в сортированные списки."""
        return {
            "ip": self.ip,
            "is_internal": self.is_internal,
            "roles": list(self.roles),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "flows_out": self.flows_out,
            "flows_in": self.flows_in,
            "bytes_out": self.bytes_out,
            "bytes_in": self.bytes_in,
            "unique_dsts": sorted(self.unique_dsts),
            "unique_srcs": sorted(self.unique_srcs),
            "sni_domains": sorted(self.sni_domains),
            "dns_names": sorted(self.dns_names),
            "findings_indices": list(self.findings_indices),
            # зарезервировано — заполняется будущими экстракторами
            "mac": self.mac,
            "hostname": self.hostname,
            "username": self.username,
            "asn": self.asn,
            "country": self.country,
        }


@dataclass
class Entities:
    internal: list[Entity]
    external: list[Entity]


def _is_special_ip(ip: str) -> bool:
    """Multicast, broadcast, loopback, link-local — не сущности."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return True
    if addr.is_multicast or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_unspecified:
        return True
    if addr.is_reserved:
        return True
    if str(addr) == "255.255.255.255":
        return True
    return False


def _touch_times(entity: Entity, ts: float | None) -> None:
    if ts is None:
        return
    if entity.first_seen is None or ts < entity.first_seen:
        entity.first_seen = ts
    if entity.last_seen is None or ts > entity.last_seen:
        entity.last_seen = ts


def _ip_from_finding(f: Finding) -> list[str]:
    """Извлечь IP-адреса, к которым относится finding.

    Возвращает список IP для привязки к сущностям.
    Пока поддерживаются:
      nxdomain_burst    — value = src_ip
      suspicious_port   — evidence: dst_ip, src_ip
    """
    ips: list[str] = []
    ftype = f.type
    value = f.value or ""

    if ftype == "nxdomain_burst":
        if value:
            ips.append(value)

    elif ftype == "suspicious_port":
        if ":" in value:
            dst_ip = value.rsplit(":", 1)[0]
            ips.append(dst_ip)
        src_ip = f.evidence.get("src_ip") if f.evidence else None
        if src_ip:
            ips.append(src_ip)

    return ips


def build_entities(
    state: CaptureState,
    findings: list[Finding],
    config: Config,
) -> Entities:
    """Собрать сущности из CaptureState и findings."""
    buckets: dict[str, Entity] = {}

    def get(ip: str) -> Entity | None:
        if _is_special_ip(ip):
            return None
        ent = buckets.get(ip)
        if ent is None:
            ent = Entity(ip=ip, is_internal=is_internal_ip(ip, config))
            buckets[ip] = ent
        return ent

    # --- flows ---
    for key, flow in state.flows.items():
        src = get(key.src_ip)
        dst = get(key.dst_ip)
        if src is not None:
            src.flows_out += 1
            src.bytes_out += flow.bytes_sent
            src.unique_dsts.add(key.dst_ip)
            _touch_times(src, flow.first_ts)
            _touch_times(src, flow.last_ts)
        if dst is not None:
            dst.flows_in += 1
            dst.bytes_in += flow.bytes_sent
            dst.unique_srcs.add(key.src_ip)
            _touch_times(dst, flow.first_ts)
            _touch_times(dst, flow.last_ts)

    # --- SNI: пишем обоим концам (через session_sni) ---
    from pcap_triage.models import get_session_sni

    for key, flow in state.flows.items():
        sni = get_session_sni(key, flow, state)
        if not sni:
            continue
        for ip in (key.src_ip, key.dst_ip):
            ent = get(ip)
            if ent is not None:
                ent.sni_domains.add(sni)

    # --- DNS по источнику ---
    for client_ip, counter in state.dns_queries_by_src.items():
        ent = get(client_ip)
        if ent is None:
            continue
        for name in counter.keys():
            ent.dns_names.add(name)

    # --- findings ---
    for idx, f in enumerate(findings):
        for ip in _ip_from_finding(f):
            ent = get(ip)
            if ent is not None and idx not in ent.findings_indices:
                ent.findings_indices.append(idx)

    # --- роли ---
    for ent in buckets.values():
        ent.roles.append("internal" if ent.is_internal else "external")

        has_findings = bool(ent.findings_indices)

        if ent.is_internal:
            if has_findings:
                ent.roles.append("victim_candidate")
            if (ent.flows_out >= config.gateway_min_flows
                    and len(ent.unique_dsts) >= config.gateway_min_unique_dsts):
                ent.roles.append("gateway_candidate")
        else:
            if has_findings:
                ent.roles.append("c2_candidate")

    # --- сортировка и разделение ---
    internal = sorted(
        (e for e in buckets.values() if e.is_internal),
        key=lambda e: (
            -len(e.findings_indices),
            -e.bytes_in - e.bytes_out,
            e.ip,
        ),
    )[: config.entities_top_n]

    external = sorted(
        (e for e in buckets.values() if not e.is_internal),
        key=lambda e: (
            -len(e.findings_indices),
            -e.bytes_in - e.bytes_out,
            e.ip,
        ),
    )[: config.entities_top_n]

    return Entities(internal=internal, external=external)