"""
LargeTransferDetector — аномально большой объём в одном flow (паре).

Сигнал: один FlowKey (или пара направлений) передал > large_transfer_min_bytes.

Что важно для триажа:
  - не «просто много байт», а КУДА много: outbound с перевесом вверх —
    эксфильтрация (T1041), inbound — выкачка payload'а/обновления (T1105).
  - internal ↔ internal (бэкап, миграция) — отдельная история, не C2.

Агрегация: пара (ip, port) + (ip, port), оба направления в один bucket.
"""
from paradox.config import Config
from paradox.models import CaptureState, Finding, FlowKey
from paradox.net_utils import is_internal_ip

# Если одна сторона >N× другой — считаем обмен односторонним.
# Порог «на глаз»: symmetric TLS handshake + data обычно дают ≥1:10.
_ASYMMETRY_RATIO = 5.0


def _pair_key(key: FlowKey) -> tuple:
    """
    Нормализованный ключ пары: (ip_a, port_a, ip_b, port_b, proto).
    Прямой и обратный flow дают одинаковый ключ.
    """
    a = (key.src_ip, key.src_port or 0)
    b = (key.dst_ip, key.dst_port or 0)
    if a <= b:
        return (a, b, key.proto)
    return (b, a, key.proto)


def _direction_for(src_ip: str, dst_ip: str, config: Config) -> str:
    """
    inbound  — внешний → внутренний
    outbound — внутренний → внешний
    internal — внутренний ↔ внутренний
    external — внешний ↔ внешний (редкость в enterprise pcap)
    """
    src_in = is_internal_ip(src_ip, config)
    dst_in = is_internal_ip(dst_ip, config)
    if src_in and dst_in:
        return "internal"
    if src_in:
        return "outbound"
    if dst_in:
        return "inbound"
    return "external"


def _mitre_hint_for(
    direction: str, bytes_in: int, bytes_out: int,
) -> tuple[str, ...]:
    """
    MITRE-подсказка по направлению + асимметрии.

    - outbound с большим upload → T1041 (Exfil Over C2 Channel)
    - inbound с большим download → T1105 (Ingress Tool Transfer)
    - internal ↔ internal → T1071.001 (Application Layer Protocol)
    - симметричный внешний обмен — без техники (T1071.001 слишком общий).
    """
    if direction == "outbound" and bytes_out > bytes_in * _ASYMMETRY_RATIO:
        return ("T1041",)
    if direction == "inbound" and bytes_in > bytes_out * _ASYMMETRY_RATIO:
        return ("T1105",)
    if direction == "internal":
        return ("T1071.001",)
    return ()


class LargeTransferDetector:
    name = "large_transfer"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        threshold = config.large_transfer_min_bytes
        include_reverse = config.large_transfer_include_reverse

        if include_reverse:
            findings = self._run_pair_mode(state, config, threshold)
        else:
            findings = self._run_single_mode(state, config, threshold)

        findings.sort(key=lambda f: -f.evidence["total_bytes"])
        return findings

    # -----------------------------------------------------------------
    # single mode — один направленный flow
    # -----------------------------------------------------------------

    def _run_single_mode(
            self, state: CaptureState, config: Config, threshold: int,
    ) -> list[Finding]:
        excluded_hosts = config.large_transfer_excluded_hosts
        excluded_uas = config.large_transfer_excluded_user_agents

        def _is_excluded(flow) -> bool:
            host = (flow.http_host or "").lower()
            ua = (flow.http_user_agent or "").lower()
            if any(h in host for h in excluded_hosts):
                return True
            if any(u.lower() in ua for u in excluded_uas):
                return True
            return False

        findings: list[Finding] = []
        for key, flow in state.flows.items():
            if _is_excluded(flow):
                continue
            if flow.bytes_sent < threshold:
                continue

            direction = _direction_for(key.src_ip, key.dst_ip, config)
            # bytes_in/out относительно internal-стороны.
            # В single mode видим только одну сторону потока.
            if direction == "outbound":
                bytes_out, bytes_in = flow.bytes_sent, 0
            elif direction == "inbound":
                bytes_out, bytes_in = 0, flow.bytes_sent
            else:
                # internal / external: понятия in/out размыты,
                # кладём всё в out — важно только направление direction.
                bytes_out, bytes_in = flow.bytes_sent, 0

            mitre = _mitre_hint_for(direction, bytes_in, bytes_out)

            findings.append(Finding(
                type="large_transfer",
                value=f"{key.src_ip} -> {key.dst_ip}:{key.dst_port}",
                confidence=0.85,
                evidence={
                    "src_ip": key.src_ip,
                    "dst_ip": key.dst_ip,
                    "src_port": key.src_port,
                    "dst_port": key.dst_port,
                    "proto": key.proto,
                    "total_bytes": flow.bytes_sent,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "packets": flow.packets,
                    "direction": direction,
                    "sni": flow.sni,
                },
                first_seen=flow.first_ts,
                last_seen=flow.last_ts,
                mitre_techniques=mitre,
            ))
        return findings

    # -----------------------------------------------------------------
    # pair mode — сумма по обоим направлениям
    # -----------------------------------------------------------------

    def _run_pair_mode(
            self, state: CaptureState, config: Config, threshold: int,
    ) -> list[Finding]:
        excluded_hosts = config.large_transfer_excluded_hosts
        excluded_uas = config.large_transfer_excluded_user_agents

        def _is_excluded(flow) -> bool:
            host = (flow.http_host or "").lower()
            ua = (flow.http_user_agent or "").lower()
            if any(h in host for h in excluded_hosts):
                return True
            if any(u.lower() in ua for u in excluded_uas):
                return True
            return False

        buckets: dict[tuple, dict] = {}

        for key, flow in state.flows.items():
            if _is_excluded(flow):
                continue
            pair = _pair_key(key)
            b = buckets.get(pair)
            if b is None:
                # Фиксируем A-сторону = src первого увиденного flow.
                # Порядок в state.flows недетерминирован между запусками,
                # но внутри одного bucket всё согласовано.
                b = {
                    "ip_a": key.src_ip, "port_a": key.src_port,
                    "ip_b": key.dst_ip, "port_b": key.dst_port,
                    "proto": key.proto,
                    "bytes_a_to_b": 0,
                    "bytes_b_to_a": 0,
                    "total_packets": 0,
                    "flows": 0,
                    "sni": None,
                    "first_seen": None,
                    "last_seen": None,
                }
                buckets[pair] = b

            if key.src_ip == b["ip_a"] and key.dst_ip == b["ip_b"]:
                b["bytes_a_to_b"] += flow.bytes_sent
            else:
                b["bytes_b_to_a"] += flow.bytes_sent

            b["total_packets"] += flow.packets
            b["flows"] += 1
            if flow.sni and not b["sni"]:
                b["sni"] = flow.sni
            if flow.first_ts is not None:
                if b["first_seen"] is None or flow.first_ts < b["first_seen"]:
                    b["first_seen"] = flow.first_ts
            if flow.last_ts is not None:
                if b["last_seen"] is None or flow.last_ts > b["last_seen"]:
                    b["last_seen"] = flow.last_ts

        findings: list[Finding] = []
        for b in buckets.values():
            total = b["bytes_a_to_b"] + b["bytes_b_to_a"]
            if total < threshold:
                continue

            direction = _direction_for(b["ip_a"], b["ip_b"], config)

            # Приводим bytes_in/out к internal-перспективе.
            if direction == "inbound":
                # ip_a — внешний, ip_b — internal: a→b это inbound
                bytes_in = b["bytes_a_to_b"]
                bytes_out = b["bytes_b_to_a"]
            else:
                # outbound / internal / external: считаем a→b за out
                bytes_out = b["bytes_a_to_b"]
                bytes_in = b["bytes_b_to_a"]

            mitre = _mitre_hint_for(direction, bytes_in, bytes_out)

            findings.append(Finding(
                type="large_transfer",
                value=f"{b['ip_a']} <-> {b['ip_b']}:{b['port_b']}",
                confidence=0.85,
                evidence={
                    "src_ip": b["ip_a"],
                    "dst_ip": b["ip_b"],
                    "src_port": b["port_a"],
                    "dst_port": b["port_b"],
                    "proto": b["proto"],
                    "total_bytes": total,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "total_packets": b["total_packets"],
                    "flow_count": b["flows"],
                    "direction": direction,
                    "sni": b["sni"],
                },
                first_seen=b["first_seen"],
                last_seen=b["last_seen"],
                mitre_techniques=mitre,
            ))
        return findings
