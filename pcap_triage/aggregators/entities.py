"""
Агрегация flows и findings в сущности (хосты).

Один IP = одна Entity. Вместо 500 flow-строк — 20-50 сущностей
с ролью и статистикой.

Роли:
  internal / external        — базовая классификация
  gateway_candidate          — internal с большим числом исходящих
  victim_candidate           — internal, который жертва
  attacker_candidate         — internal/external, который атакует
  c2_candidate               — external с findings
  domain_controller          — internal с сервисным трафиком
  pivot                      — victim + attacker (см. contradictions)

Про pivot:
  Роль ставится, если для IP сработало правило victim_makes_attack:
  хост фигурирует и как жертва, и как атакующий. Роль victim_candidate
  при этом сохраняется (актив, который надо спасать), pivot — метка
  поверх неё. В отчёте помогает отличить «просто жертву» от
  «скомпрометированной жертвы, которая уже движется дальше».
"""
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any

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
    service_flows_in: int = 0
    service_unique_srcs: set[str] = field(default_factory=set)
    findings_indices: list[int] = field(default_factory=list)

    mac: str | None = None
    hostname: str | None = None
    username: str | None = None
    realm: str | None = None
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
            "service_flows_in": self.service_flows_in,
            "service_unique_srcs": sorted(self.service_unique_srcs),
            "mac": self.mac,
            "hostname": self.hostname,
            "username": self.username,
            "realm": self.realm,
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

    Стратегия:
      1. Explicit для findings, где IP зашит в value.
      2. Universal — src_ip / dst_ip с top-level Finding.

    v0.8.0: top-level приоритет, evidence fallback. После шага 2
    pipeline._normalize_finding заполняет f.src_ip / f.dst_ip из
    evidence — читаем их напрямую. Fallback оставлен на переходный
    период; уйдёт в v0.9, когда детекторы начнут заполнять контракт
    сами и дубли в evidence уберутся.
    """
    result: list[tuple[str, str]] = []
    ftype = f.type
    value = f.value or ""
    ev = f.evidence or {}

    # v0.8.0: top-level приоритет, evidence fallback.
    src_ip = f.src_ip or ev.get("src_ip")
    dst_ip = f.dst_ip or ev.get("dst_ip")

    # --- explicit: value содержит IP ---

    if ftype == "nxdomain_burst":
        if value:
            result.append((value, "src"))
        return result

    if ftype == "suspicious_port":
        if ":" in value:
            dst_from_value = value.rsplit(":", 1)[0]
            result.append((dst_from_value, "dst"))
        if src_ip:
            result.append((src_ip, "src"))
        return result

    # --- universal ---

    # (Раньше здесь был блок "if dst_ip is None and ftype == command_injection"
    # — он был no-op даже в старой версии: dst_ip только что прочитан
    # из того же ev.get("dst_ip"). Убран при переходе на top-level.)

    if src_ip:
        result.append((src_ip, "src"))
    if dst_ip:
        result.append((dst_ip, "dst"))
    return result


def _pivot_subjects(contradictions: list[Any] | None) -> set[str]:
    """
    Собрать IP, для которых сработало правило victim_makes_attack.

    Duck-typing: contradictions/ импортируется в pipeline, а entities.py
    не должен от него зависеть (циклы импортов). Контракт: у объекта
    есть атрибуты .rule (str) и .subject (str).
    """
    if not contradictions:
        return set()
    out: set[str] = set()
    for c in contradictions:
        if getattr(c, "rule", None) == "victim_makes_attack":
            subj = getattr(c, "subject", None)
            if subj:
                out.add(subj)
    return out


def build_entities(
    state: CaptureState,
    findings: list[Finding],
    config: Config,
    contradictions: list[Any] | None = None,
) -> Entities:
    """
    Собрать сущности из CaptureState и findings.

    contradictions — опционально: результат run_all из contradictions/.
    Нужен для проставления роли pivot. Старые вызовы без него
    работают как раньше.
    """
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

    # --- сервисный трафик к DC: порты 88, 389, 445, 3268, 636 ---
    dc_ports = config.dc_service_ports
    for key, flow in state.flows.items():
        if key.dst_port not in dc_ports:
            continue
        dst = get(key.dst_ip)
        src = get(key.src_ip)
        if dst is None or src is None:
            continue
        if not src.is_internal:
            continue
        dst.service_flows_in += 1
        dst.service_unique_srcs.add(key.src_ip)

    # --- SNI: пишем обоим концам ---
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

    # --- host identity: MAC + hostname + username + realm ---
    # ВАЖНО: до findings, вне цикла по findings (был O(N×M)).
    for ip, ident in state.host_identities.items():
        ent = get(ip)
        if ent is None:
            continue
        if ident.mac:
            ent.mac = ident.mac
        if ident.hostnames:
            ent.hostname = sorted(ident.hostnames)[0]
        if ident.username:
            ent.username = ident.username
        if ident.realm:
            ent.realm = ident.realm

    # --- findings ---
    role_tags: dict[str, set[str]] = {}

    for idx, f in enumerate(findings):
        for ip, side in _ips_from_finding(f):
            ent = get(ip)
            if ent is None:
                continue
            if idx not in ent.findings_indices:
                ent.findings_indices.append(idx)

            tags = role_tags.setdefault(ip, set())
            ftype = f.type

            if ftype in ("brute_force", "vulnerable_path",
                         "ftp_brute_force", "command_injection",
                         "port_scan", "web_scanner"):
                # src = атакующий, dst = цель
                if side == "src":
                    tags.add("attacker_tag")
                else:
                    tags.add("victim_tag")

            elif ftype == "lateral_movement":
                # src = скомпрометированный хост (pivot), dst = следующая цель
                # Помечаем src как attacker (он атакует), dst как victim.
                # Роль victim_candidate у pivot'а выигрывает по приоритету
                # (см. ниже), потому что у него уже есть victim_tag от
                # brute_force.
                if side == "src":
                    tags.add("attacker_tag")
                else:
                    tags.add("victim_tag")

            elif ftype == "script_download":
                # ИНВЕРТИРОВАНО: src = жертва (качает payload),
                # dst = источник malware (attacker)
                if side == "src":
                    tags.add("victim_tag")
                else:
                    tags.add("attacker_tag")

            elif ftype in ("beaconing", "dns_tunneling"):
                # src = жертва (отстукивает), dst = C2
                if side == "src":
                    tags.add("victim_tag")
                else:
                    tags.add("attacker_tag")

            elif ftype == "large_transfer":
                # large_transfer — статистика объёма, не роль.
                # Шлюз, качающий 2 GB обновлений, — не victim и не attacker.
                # Роль определится ниже через flows_out / unique_dsts
                # (gateway_candidate) или останется без роли, если хост
                # просто много передал. Помечать здесь victim/attacker
                # нельзя: вытесняет настоящих жертв из топа сущностей
                # и ломает TL;DR.
                #
                # findings_indices при этом всё равно пополняется
                # (строки выше) — large_transfer виден в findings
                # сущности и в отчёте, просто без роли.
                pass

            elif ftype in ("ja3_malware", "sni_without_dns",
                           "dga_domain", "typosquatting",
                           "cloud_tunnel", "ip_check_service"):
                # Внешние индикаторы, src = инициатор
                if side == "src":
                    tags.add("victim_tag")
                else:
                    tags.add("attacker_tag")

            elif ftype == "nxdomain_burst":
                # src = жертва: инфекция резолвит DGA-домены,
                # либо сканер перебирает мусорные имена.
                # Finding приходит только для src-стороны.
                if side == "src":
                    tags.add("victim_tag")
                else:
                    tags.add("attacker_tag")

            elif ftype == "suspicious_port":
                # src = жертва (внутренний хост стучится наружу),
                # dst = C2 (внешний сервер на подозрительном порту)
                if side == "src":
                    tags.add("victim_tag")
                else:
                    tags.add("attacker_tag")

            else:
                # Fallback: src = attacker, dst = victim
                if side == "src":
                    tags.add("attacker_tag")
                else:
                    tags.add("victim_tag")

    # --- pivot-субъекты из contradictions ---
    pivot_ips = _pivot_subjects(contradictions)

    # --- роли ---
    for ent in buckets.values():
        ent.roles.append("internal" if ent.is_internal else "external")

        has_findings = bool(ent.findings_indices)
        tags = role_tags.get(ent.ip, set())
        has_attacker = "attacker_tag" in tags
        has_victim = "victim_tag" in tags

        if ent.is_internal:
            # 1. Приоритет: DC
            if (ent.service_flows_in >= config.dc_min_service_flows
                    and len(ent.service_unique_srcs) >= config.dc_min_unique_srcs):
                ent.roles.append("domain_controller")

            # 2. Victim > attacker: жертва — актив, который надо спасать.
            # Pivot (скомпрометированная жертва, атакующая дальше) —
            # тоже victim: у неё есть brute_force dst.
            elif has_victim:
                ent.roles.append("victim_candidate")
            elif has_attacker:
                ent.roles.append("attacker_candidate")
            elif has_findings:
                ent.roles.append("victim_candidate")

            # 2b. pivot — метка поверх victim_candidate. Ставится,
            # если правило victim_makes_attack нашло у хоста
            # одновременные victim_of и attacker_of факты.
            # Роль НЕ заменяет victim_candidate, а дополняет:
            # актив тот же, интерпретация другая.
            if ent.ip in pivot_ips:
                ent.roles.append("pivot")

            # 3. Gateway — только если не DC и не attacker
            if ("domain_controller" not in ent.roles
                    and "attacker_candidate" not in ent.roles
                    and ent.flows_out >= config.gateway_min_flows
                    and len(ent.unique_dsts) >= config.gateway_min_unique_dsts):
                ent.roles.append("gateway_candidate")
        else:
            # external: attacker и C2 — не взаимоисключающие.
            # Внешний сервер с finding'ом = C2-кандидат.
            # Если активный attacker_tag (реально атакует) — добавляем.
            if has_attacker:
                ent.roles.append("attacker_candidate")
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