"""
Правило direct_ip_no_dns (hardcoded IP / прямой C2).

Случай: клиент ходит на внешние IP, но в захвате не сделал ни одного
DNS-запроса. Значит — либо резолв был раньше (кеш, не в этом pcap),
либо IP зашит в конфиг.

Что это значит для триажа:
  - Легитимно: клиент с постоянным кешем (долгоживущий процесс),
    обращения к CDN/сервисам, чей IP не меняется годами.
  - Подозрительно: свежий процесс ходит на hardcoded IP без резолва.
    Типично для C2 без DGA, скриптов, малвари.

Ограничение: DNS-ответов у нас нет (парсер A-записей не сделан).
Поэтому «клиент без DNS-запросов» — грубая эвристика. Если клиент
в том же файле делал DNS-запросы хоть к чему-то — правило молчит.
Это осознанно: снижаем FP, теряем чувствительность.

Фильтры:
  - direct_ip_connect только на external dst (внутренний обмен — не сюда).
  - min_connections: клиент с одним исходящим на IP — шум. Требуем
    хотя бы 3 уникальных внешних dst или ≥10 flows к одному dst.

Severity: medium. Confidence = 0.7 — эвристика, есть FP на кешах.

Отличие от beaconing: тот ловит периодичность (jitter, длительность).
Этот ловит «нет DNS вообще». Могут срабатывать на одной сессии —
тогда в отчёте два сигнала: «периодично» и «без резолва». Это
правильно: разные признаки, разные confirmation.
"""
from __future__ import annotations

from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.base import Contradiction, Fact


_MIN_UNIQUE_DSTS = 3
_MIN_FLOWS_TO_ONE = 10


class DirectIpNoDnsRule:
    name = "direct_ip_no_dns"
    severity_base = "medium"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        from pcap_triage.contradictions.facts import extract_direct_ip_facts
        return extract_direct_ip_facts(state, config)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        by_subject: dict[str, dict[str, list[Fact]]] = defaultdict(
            lambda: {"direct_ip_connect": [], "makes_dns_queries": []}
        )
        for f in facts:
            if f.predicate in ("direct_ip_connect", "makes_dns_queries"):
                by_subject[f.subject][f.predicate].append(f)

        out: list[Contradiction] = []
        for src, buckets in by_subject.items():
            connects = buckets["direct_ip_connect"]
            dns = buckets["makes_dns_queries"]

            if not connects:
                continue
            if dns:
                # Клиент делал хоть какие-то DNS-запросы — не наш кейс.
                # Слишком много FP: процессы с долгим кешем, или клиент
                # резолвил другой домен в этом же pcap.
                continue

            # Фильтр по объёму: единичные connect'ы не интересны.
            unique_dsts = len(connects)
            max_flows_one_dst = max(
                len(f.evidence.get("ports", [])) for f in connects
            )
            if (unique_dsts < _MIN_UNIQUE_DSTS
                    and max_flows_one_dst < _MIN_FLOWS_TO_ONE):
                continue

            # Топ-3 по байтам — самые значимые сессии.
            connects_sorted = sorted(
                connects,
                key=lambda f: -f.evidence.get("bytes_sent", 0),
            )
            top = connects_sorted[:3]
            top_str = ", ".join(
                f"{f.value}({f.evidence.get('bytes_sent', 0)} Б)"
                for f in top
            )

            total_bytes = sum(
                f.evidence.get("bytes_sent", 0) for f in connects
            )

            hint = (
                f"{src}: {unique_dsts} прямых IP-подключений наружу, "
                f"DNS-запросов — ноль. Топ: {top_str}. "
                f"Суммарно {total_bytes} Б. Проверить, что за процесс "
                f"ходит по hardcoded IP: C2 без домена, легитимный "
                f"сервис с постоянным адресом или кешированный резолв."
            )

            out.append(Contradiction(
                rule=self.name,
                subject=src,
                facts=top,
                severity=self.severity_base,
                confidence=0.7,
                likely_causes=[
                    "Hardcoded IP C2: малварь без домена, прямая связь",
                    "Скрипт/сервис с зашитым IP в конфиге",
                    "Долгоживущий процесс с закешированным DNS "
                    "(резолв был до начала захвата)",
                    "NAT/proxy: трафик клиентов идёт через один хост",
                    "FP: DNS-запрос был, но через DoH/DoT (не видим)",
                ],
                resolution_hint=hint,
            ))

        return out