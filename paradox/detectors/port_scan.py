"""
PortScanDetector — горизонтальное сканирование: один src_ip, много dst_ip,
один dst_port.

Сигнал: src_ip обратился к >= N разным dst_ip на один dst_port, причём
к каждому — не более M flow'ов (сканер обычно делает 1 SYN на цель).

Отличие от suspicious_port:
  - suspicious_port  → finding per (dst_ip, dst_port), много findings
  - port_scan        → finding per (src_ip, dst_port), один finding
                       с evidence: distinct_dsts, top_dsts

Отличие от brute_force:
  - brute_force → много flow'ов к ОДНОМУ dst_ip
  - port_scan   → по 1-2 flow к КАЖДОМУ из многих dst_ip

Если у src_ip много flow'ов ко многим dst_ip — это в основном браузер
с параллельными соединениями. Отсеиваем через max_flows_per_dst.

Порты 80/443 исключены полностью: скан на них неотличим от браузера
(675 сайтов за день — норма), а rate/flow_count сигналы там бесполезны.
"""
from collections import Counter, defaultdict

from paradox.config import Config
from paradox.models import CaptureState, Finding


class PortScanDetector:
    name = "port_scan"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        # (src_ip, dst_port) → Counter[dst_ip]
        scans: dict[tuple[str, int], Counter] = defaultdict(Counter)
        # (src_ip, dst_port) → [first_ts, last_ts]
        scan_ts: dict[tuple[str, int], list[float]] = defaultdict(
            lambda: [float("inf"), 0.0]
        )

        for key, flow in state.flows.items():
            if key.proto != "tcp":
                continue
            if key.dst_port is None:
                continue
            group = (key.src_ip, key.dst_port)
            scans[group][key.dst_ip] += 1
            if flow.first_ts is not None and flow.first_ts < scan_ts[group][0]:
                scan_ts[group][0] = flow.first_ts
            if flow.last_ts is not None and flow.last_ts > scan_ts[group][1]:
                scan_ts[group][1] = flow.last_ts

        findings: list[Finding] = []
        for (src_ip, dst_port), dst_counts in scans.items():
            # 80/443 — браузер, не скан. См. docstring.
            if dst_port in config.port_scan_excluded_ports:
                continue

            distinct_dsts = len(dst_counts)
            if distinct_dsts < config.port_scan_min_distinct_dsts:
                continue

            # Если к большинству целей много flow'ов — это не скан.
            # Считаем долю «тонких» целей (≤ max_flows_per_dst).
            thin = sum(
                1 for c in dst_counts.values()
                if c <= config.port_scan_max_flows_per_dst
            )
            if thin / distinct_dsts < 0.7:
                continue

            total_flows = sum(dst_counts.values())
            top_dsts = [
                {"ip": ip, "flows": c}
                for ip, c in dst_counts.most_common(10)
            ]

            confidence = 0.9 if distinct_dsts >= 30 else 0.75
            first_ts, last_ts = scan_ts[(src_ip, dst_port)]
            findings.append(Finding(
                type="port_scan",
                value=f"{src_ip} -> *:{dst_port}",
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "distinct_dsts": distinct_dsts,
                    "total_flows": total_flows,
                    "thin_targets": thin,
                    "top_dsts": top_dsts,
                    "threshold": config.port_scan_min_distinct_dsts,
                },
                first_seen=(
                    first_ts if first_ts != float("inf") else None
                ),
                last_seen=last_ts or None,
            ))

        findings.sort(key=lambda f: (-f.confidence, f.value))
        return findings
