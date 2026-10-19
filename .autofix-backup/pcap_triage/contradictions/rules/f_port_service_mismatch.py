"""
Правило port_service_mismatch (протокольный туннель).

Случай: порт предназначен для одного сервиса, а внутри — другой
протокол. Классика обхода firewall: SSH-туннель на 443 (или наоборот),
HTTP внутри SMB, TLS поверх DNS.

Как определяется «предназначение порта» — config.port_service_allowed:
ключ — порт, значение — набор разрешённых протоколов. Протокол
детектируется в facts.py: "tls" (ClientHello) или "http" (HTTP-метод).

Что НЕ ловим:
  - Нестандартные порты (8443, 9443, 5000, ...) — там нет
    однозначного предназначения, любой протокол ожидаем.
  - Порт 443 — вне таблицы, чтобы не FP'ить на h2c / HTTP-over-443.
  - SMTP/POP3/IMAP разрешают tls (STARTTLS/STLS узаконен).
  - Порт 80 разрешает tls (HTTPS на 80 иногда встречается).

Severity:
  - high:   критичные сервисы — 22, 23, 53, 139, 445, 3389,
            5900 (VNC), 6379 (Redis). Туннель поверх них — палево.
  - medium: сервисы БД и почты — 25, 110, 143, 1433, 1521,
            3306, 5432, 27017.

Confidence = 0.9. Детекторы протокола надёжные: TLS handshake и
HTTP-метод — не эвристика. Снижаем с 0.95 до 0.9 на всякий случай:
возможны легитимные сервисы на нестандартном порту (админ ошибся).

Один Contradiction на (src_ip, dst_ip, dst_port). Если на flow и TLS,
и HTTP — оба в одном срабатывании.
"""
from __future__ import annotations

from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.base import (
    Contradiction,
    Fact,
    SEVERITY_ORDER,
)


# Порты критичных сервисов: туннель поверх них — high.
# Остальные порты из config.port_service_allowed — medium.
_HIGH_SEVERITY_PORTS: frozenset[int] = frozenset({
    22,     # SSH
    23,     # Telnet
    53,     # DNS
    139,    # NetBIOS
    445,    # SMB
    3389,   # RDP
    5900,   # VNC
    6379,   # Redis
})


class PortServiceMismatchRule:
    name = "port_service_mismatch"
    severity_base = "high"

    def extract_facts(
            self,
            state: CaptureState,
            findings: list[Finding],
            config: Config,
    ) -> list[Fact]:
        self._allowed = config.port_service_allowed
        from pcap_triage.contradictions.facts import (
            extract_protocol_on_port_facts,
        )
        return extract_protocol_on_port_facts(state, config)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        # find_contradictions не получает config по контракту Protocol —
        # читаем на месте.
        from pcap_triage.config import Config as _Cfg
        allow = getattr(self, "_allowed", {})

        # Группировка: (src_ip, dst_ip, dst_port) → список фактов.
        groups: dict[
            tuple[str, str, int], list[Fact],
        ] = defaultdict(list)
        for f in facts:
            if f.predicate != "protocol_on_port":
                continue
            dst_ip = f.evidence.get("dst_ip")
            dst_port = f.evidence.get("dst_port")
            if dst_ip is None or dst_port is None:
                continue
            groups[(f.subject, dst_ip, dst_port)].append(f)

        out: list[Contradiction] = []
        for (src, dst, port), fl in groups.items():
            expected = allow.get(port)
            if expected is None:
                # Порт без явных ожиданий — не наше дело.
                continue

            observed = {f.value for f in fl}
            if observed.issubset(expected):
                # Всё в рамках ожидаемого.
                continue

            unexpected = observed - expected

            severity = (
                "high" if port in _HIGH_SEVERITY_PORTS else "medium"
            )

            # Первичный факт — самый уверенный из unexpected.
            unexpected_facts = [f for f in fl if f.value in unexpected]
            primary = max(unexpected_facts, key=lambda f: f.confidence)

            exp_str = ", ".join(sorted(expected))
            unexp_str = ", ".join(sorted(unexpected))

            # Дополнительный контекст, если он есть в evidence.
            context_parts: list[str] = []
            if primary.evidence.get("sni"):
                context_parts.append(f"SNI=`{primary.evidence['sni']}`")
            if primary.evidence.get("host"):
                context_parts.append(f"Host=`{primary.evidence['host']}`")
            if primary.evidence.get("method"):
                context_parts.append(f"method=`{primary.evidence['method']}`")
            context = " · ".join(context_parts) if context_parts else "—"

            hint = (
                f"{src} → {dst}:{port} — на порту ожидался "
                f"[{exp_str}], обнаружен [{unexp_str}]. {context}. "
                f"Классика протокольного туннеля: клиент прячет "
                f"{unexp_str} под порт {port}, чтобы пройти firewall "
                f"или IDS. Проверить назначение соединения и "
                f"содержимое сессии."
            )

            out.append(Contradiction(
                rule=self.name,
                subject=src,
                facts=[primary],
                severity=severity,
                confidence=0.9,
                likely_causes=[
                    "Протокольный туннель: SSH-over-HTTP, TLS-over-DNS, "
                    "HTTP-over-SMB и т.п.",
                    "Сервис на нестандартном порту (админ ошибся "
                    "с конфигом) — легитимно, но полезно знать",
                    "Security scanner / pentest: инструмент проверяет "
                    "доступность порта любым протоколом",
                    "Корпоративный прокси / MPLS-инкапсуляция",
                    "FP: ложное срабатывание парсера HTTP/TLS "
                    "на не-HTTP/TLS payload",
                ],
                resolution_hint=hint,
            ))

        out.sort(key=lambda c: (
            SEVERITY_ORDER.get(c.severity, 99),
            -c.confidence,
            c.subject,
        ))
        return out