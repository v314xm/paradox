"""
Агрегация flows и findings в сущности (хосты).

Один IP = одна Entity. Вместо 500 flow-строк — 20-50 сущностей
с ролью и статистикой.

Роли:
  internal / external        — базовая классификация
  gateway_candidate          — internal с большим числом исходящих
  victim_candidate           — internal, который жертва (brute_force dst,
                               nxdomain_burst src, suspicious_port src)
  attacker_candidate         — internal, который атакует (brute_force src)
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
    if addr.is_unspecified or addr.is_reserved:
        return True
    if str(addr) == "255.255.255.255":
        return True
    if addr.version == 4:
        last_octet = int(str(addr).rsplit(".", 1)[1])
        if last_octet == 0 or last_octet == 255:
            return True
    return False


def _touch_times(entity: Entity, ts: float | None) -> None:
    if ts is None:
        return
    if entity.first_seen is None or ts < entity.first_seen:
        entity.first_seen = ts
    if entity.last_seen is None or ts > entity.last_seen:
        entity.last_seen = ts


def _ips_from_finding(f: Finding) -> list[tuple[str, str]]:
    """
    Извлечь IP-адреса + указание стороны (src/dst) из finding.

    Возвращает список (ip, side), где side = "src" или "dst".

    Поддерживаются:
      nxdomain_burst    — value = src_ip (сторона src)
      suspicious_port   — value = "dst_ip:port" + evidence.src_ip
      brute_force       — evidence.src_ip (attacker) + evidence.dst_ip (victim)
    """
    result: list[tuple[str, str]] = []
    ftype = f.type
    value = f.value or ""

    if ftype == "nxdomain_burst":
        if value:
            result.append((value, "src"))

    elif ftype == "suspicious_port":
        if ":" in value:
            dst_ip = value.rsplit(":", 1)[0]
            result.append((dst_ip, "dst"))
        src_ip = f.evidence.get("src_ip") if f.evidence else None
        if src_ip:
            result.append((src_ip, "src"))

    elif ftype == "brute_force":
        ev = f.evidence or {}
        src_ip = ev.get("src_ip")
        dst_ip = ev.get("dst_ip")
        if src_ip:
            result.append((src_ip, "src"))
        if dst_ip:
            result.append((dst_ip, "dst"))

    return result


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
    role_tags: dict[str, set[str]] = {}

    for idx, f in enumerate(findings):
        for ip, side in _ips_from_finding(f):
            ent = get(ip)
            if ent is None:
                continue
            if idx not in ent.findings_indices:
                ent.findings_indices.append(idx)
            if f.type == "brute_force":
                tags = role_tags.setdefault(ip, set())
                tags.add("brute_force_src" if side == "src" else "brute_force_dst")

    # --- роли ---
    for ent in buckets.values():
        ent.roles.append("internal" if ent.is_internal else "external")

        has_findings = bool(ent.findings_indices)
        tags = role_tags.get(ent.ip, set())

        if ent.is_internal:
            if "brute_force_src" in tags:
                ent.roles.append("attacker_candidate")
            if "brute_force_dst" in tags:
                ent.roles.append("victim_candidate")
            elif has_findings and "attacker_candidate" not in ent.roles:
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