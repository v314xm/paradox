"""
LongConnectionDetector — долгая TCP-сессия наружу без имени.

Сигнал: внутренний клиент установил TCP-сессию к внешнему адресу
(виден SYN) и держит её дольше получаса, не предъявив ни SNI, ни
HTTP Host.

Что это может быть:
  - keepalive C2, который живёт в одном соединении и не шлёт
    периодических новых подключений (beaconing его не увидит);
  - reverse shell поверх одного TCP-соединения;
  - туннель на нестандартном порту.

Что отсеивается:
  - не-TCP: у UDP «поток» — это агрегат по 5-tuple за весь захват,
    его длительность равна горизонту записи, а не жизни сессии;
  - обратное направление и потоки без SYN: сессию надо видеть
    с начала;
  - внутренний обмен: долгий SMB/RDP внутри сети — норма, им
    занимается lateral_movement;
  - сессии с именем (SNI/Host) из allowlist: push-каналы Windows,
    обновления, CDN;
  - порты служб, для которых долгая сессия штатна (SSH, почта,
    VPN, БД, RDP/VNC, локальные прокси).

Объём здесь не проверяется: large_transfer и reverse_asymmetry
отвечают за количество байт, это правило — про длительность.
"""
from paradox.config import Config
from paradox.models import CaptureState, Finding
from paradox.net_utils import ip_scope


def _in_allowlist(name: str | None, allowlist: frozenset[str]) -> bool:
    if not name:
        return False
    name = name.lower().strip(".")
    return any(
        name == entry or name.endswith("." + entry)
        for entry in allowlist
    )


class LongConnectionDetector:
    name = "long_connections"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []

        for key, flow in state.flows.items():
            if key.proto != "tcp":
                continue
            if key.dst_port is None:
                continue
            # Сессия должна быть установлена в захвате: без SYN
            # длительность считается от первого увиденного пакета.
            if flow.initiated_by_src is not True:
                continue
            if ip_scope(key.src_ip, config) != "internal":
                continue
            if ip_scope(key.dst_ip, config) != "external":
                continue
            if flow.duration < config.long_connection_min_duration_sec:
                continue
            if flow.packets < config.long_connection_min_packets:
                continue

            name = flow.sni or flow.http_host
            if _in_allowlist(name, config.long_connection_allowlist_suffixes):
                continue
            if key.dst_port in config.long_connection_excluded_ports:
                continue

            findings.append(Finding(
                type="long_connection",
                value=f"{key.src_ip} -> {key.dst_ip}:{key.dst_port}",
                src_ip=key.src_ip,
                dst_ip=key.dst_ip,
                dst_port=key.dst_port,
                confidence=0.55,
                evidence={
                    "src_ip": key.src_ip,
                    "dst_ip": key.dst_ip,
                    "dst_port": key.dst_port,
                    "duration_sec": round(flow.duration, 2),
                    "duration_min": round(flow.duration / 60.0, 1),
                    "packets_total": flow.packets,
                    "bytes_sent": flow.bytes_sent,
                    "sni": flow.sni,
                    "http_host": flow.http_host,
                },
                first_seen=flow.first_ts,
                last_seen=flow.last_ts,
            ))

        findings.sort(key=lambda f: -f.evidence["duration_sec"])
        return findings
