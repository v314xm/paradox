"""
RareExternalIPDetector — одиночный контакт с внешним IP без DNS.

Сигнал: внутренний клиент открыл 1–2 соединения к внешнему адресу,
которого нет в DNS-ответах захвата и который не назван ни через SNI,
ни через HTTP Host.

Чем отличается от правила `direct_ip_no_dns`:
  - правило смотрит на клиента целиком и требует ≥3 адресатов или
    ≥10 flows к одному; здесь единица — конкретный адрес, и хватает
    одного соединения;
  - здесь есть положительное доказательство «адрес не резолвился»:
    DNS в захвате виден, и этого IP в ответах нет.

Почему фильтр по DNS обязателен: наивное «1–2 flow к внешнему IP»
даёт 52 кандидата на 2025-06-13 и 36 на FIRST-2015 — все легитимные
сервисы (обновления, телеметрия, CDN). Сравнение с
`state.dns_answers_by_ip` обнуляет шум на обоих эталонах.

Осознанные ограничения:
  - если в захвате нет ни одного DNS-ответа, детектор молчит: без
    DNS нельзя отличить «адрес зашит» от «резолв шёл мимо захвата»;
  - TCP-поток без SYN (начался до захвата) пропускается: DNS мог
    быть до начала записи;
  - адреса из allowlist и инфраструктурные порты (DNS, NTP, mDNS,
    LLMNR, SSDP, DoT) не считаются.

Типичный TP: малварь с зашитым IP C2, дроппер, «звонок домой» после
заражения без домена.
"""
from collections import Counter

from paradox.config import Config
from paradox.models import CaptureState, Finding
from paradox.net_utils import ip_scope


class RareExternalIPDetector:
    name = "rare_external_ip"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        # Без видимого DNS утверждать «адрес не резолвился» нельзя.
        if not state.dns_answers_by_ip:
            return []

        excluded_ports = config.rare_external_ip_excluded_ports
        allowlist = config.rare_external_ip_allowlist_ips

        buckets: dict[str, dict] = {}

        for key, flow in state.flows.items():
            if key.proto not in ("tcp", "udp"):
                continue
            if key.dst_port is None:
                continue
            if key.dst_ip in state.dns_answers_by_ip:
                continue
            if key.dst_ip in allowlist:
                continue
            if key.dst_port in excluded_ports:
                continue
            if ip_scope(key.src_ip, config) != "internal":
                continue
            if ip_scope(key.dst_ip, config) != "external":
                continue
            # TCP без SYN — поток начался до захвата: DNS мог быть
            # раньше, обвинять в «нет резолва» нельзя.
            if key.proto == "tcp" and flow.initiated_by_src is not True:
                continue

            b = buckets.get(key.dst_ip)
            if b is None:
                b = buckets[key.dst_ip] = {
                    "flows": 0,
                    "src_ips": set(),
                    "ports": Counter(),
                    "packets": 0,
                    "bytes_sent": 0,
                    "named": False,
                    "first_seen": None,
                    "last_seen": None,
                }

            b["flows"] += 1
            b["src_ips"].add(key.src_ip)
            b["ports"][key.dst_port] += 1
            b["packets"] += flow.packets
            b["bytes_sent"] += flow.bytes_sent
            # SNI/Host на любом соединении к адресу — имя известно,
            # это уже не «безымянный» контакт.
            if flow.sni or flow.http_host:
                b["named"] = True
            if flow.first_ts is not None:
                if b["first_seen"] is None or flow.first_ts < b["first_seen"]:
                    b["first_seen"] = flow.first_ts
            if flow.last_ts is not None:
                if b["last_seen"] is None or flow.last_ts > b["last_seen"]:
                    b["last_seen"] = flow.last_ts

        findings: list[Finding] = []
        for dst_ip, b in buckets.items():
            if b["named"]:
                continue
            if b["flows"] > config.rare_external_ip_max_connections:
                continue

            dst_port = b["ports"].most_common(1)[0][0]
            src_ips = sorted(b["src_ips"])

            findings.append(Finding(
                type="rare_external_ip",
                value=f"{dst_ip}:{dst_port}",
                src_ip=src_ips[0],
                dst_ip=dst_ip,
                dst_port=dst_port,
                confidence=0.55,
                evidence={
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "dst_ports": sorted(b["ports"]),
                    "src_ips": src_ips,
                    "flow_count": b["flows"],
                    "packets_total": b["packets"],
                    "bytes_sent": b["bytes_sent"],
                    "resolved_by_dns": False,
                    "named": False,
                },
                first_seen=b["first_seen"],
                last_seen=b["last_seen"],
            ))

        findings.sort(key=lambda f: (f.dst_ip or "", f.value))
        return findings
