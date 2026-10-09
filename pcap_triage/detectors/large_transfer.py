"""
LargeTransferDetector — аномально большой объём в одном flow.

Сигнал: один FlowKey (5-tuple) передал > large_transfer_min_bytes.
Пример: 80.64.102.71 → 192.168.1.1, 123 MB inbound — в разы больше
любого нормального сеанса.

Опционально (large_transfer_include_reverse=True) — суммирует
байты обратного flow (dst → src), потому что при двунаправленном
обмене интересен общий объём. Один finding на пару (src, dst),
если она превышает порог.

Агрегация: ключ — frozenset({src_ip, dst_ip}) + порты, чтобы
прямой и обратный flow попали в один bucket.
"""
from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding, FlowKey


def _pair_key(key: FlowKey) -> tuple:
    """
    Нормализованный ключ пары: (ip_a, port_a, ip_b, port_b).
    Прямой и обратный flow дают одинаковый ключ.
    """
    a = (key.src_ip, key.src_port or 0)
    b = (key.dst_ip, key.dst_port or 0)
    if a <= b:
        return (a, b, key.proto)
    return (b, a, key.proto)


class LargeTransferDetector:
    name = "large_transfer"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        threshold = config.large_transfer_min_bytes
        include_reverse = config.large_transfer_include_reverse

        if include_reverse:
            findings = self._run_pair_mode(state, config, threshold)
        else:
            findings = self._run_single_mode(state, threshold)

        findings.sort(key=lambda f: -f.evidence["total_bytes"])
        return findings

    def _run_single_mode(
        self, state: CaptureState, threshold: int,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key, flow in state.flows.items():
            if flow.bytes_sent < threshold:
                continue
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
                    "bytes": flow.bytes_sent,
                    "packets": flow.packets,
                    "direction": "single",
                    "sni": flow.sni,
                },
                first_seen=flow.first_ts,
                last_seen=flow.last_ts,
            ))
        return findings

    def _run_pair_mode(
        self, state: CaptureState, config: Config, threshold: int,
    ) -> list[Finding]:
        # Агрегация по нормализованной паре — включает оба направления
        buckets: dict[tuple, dict] = {}

        for key, flow in state.flows.items():
            pair = _pair_key(key)
            b = buckets.setdefault(pair, {
                "src_ip": key.src_ip,     # первый по порядку в state
                "dst_ip": key.dst_ip,
                "src_port": key.src_port,
                "dst_port": key.dst_port,
                "proto": key.proto,
                "total_bytes": 0,
                "total_packets": 0,
                "flows": 0,
                "sni": None,
                "first_seen": None,
                "last_seen": None,
            })
            b["total_bytes"] += flow.bytes_sent
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
        for pair, b in buckets.items():
            if b["total_bytes"] < threshold:
                continue

            # Направление: если src внутренний, а dst внешний — inbound,
            # и наоборот. Для случая internal → internal — "internal".
            from pcap_triage.net_utils import classify_direction
            direction = classify_direction(b["src_ip"], b["dst_ip"], config)

            findings.append(Finding(
                type="large_transfer",
                value=f"{b['src_ip']} <-> {b['dst_ip']}:{b['dst_port']}",
                confidence=0.85,
                evidence={
                    "src_ip": b["src_ip"],
                    "dst_ip": b["dst_ip"],
                    "src_port": b["src_port"],
                    "dst_port": b["dst_port"],
                    "proto": b["proto"],
                    "total_bytes": b["total_bytes"],
                    "total_packets": b["total_packets"],
                    "flow_count": b["flows"],
                    "direction": direction,
                    "sni": b["sni"],
                },
                first_seen=b["first_seen"],
                last_seen=b["last_seen"],
            ))
        return findings