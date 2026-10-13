"""
Правило victim_makes_attack (PIVOT).

Случай: хост X фигурирует в findings и как жертва (кто-то атакует X),
и как атакующий (X атакует Y). В норме хост — либо жертва, либо
атакующий; обе роли одновременно требуют объяснения.

Возможные причины:
  - pivot: X скомпрометирован и используется для lateral movement.
  - authorized scanner: X сканирует кого-то, и его сканируют.
  - NAT/proxy: одна IP обслуживает несколько хостов.
  - FP одной из эвристик.

Confidence = min(conf_victim, conf_attacker, 0.90). Потолок 0.90 —
правило эвристическое: без проверки timestamps нельзя утверждать pivot.

Severity: critical. Pivot — самый неприятный сценарий: атакующий
уже внутри и движется дальше.

На CyberCampTask: 192.168.1.12 — жертва от 10.0.1.50, но делает
lateral на 192.168.1.1 → отдельный Contradiction severity=critical.

На FIN-2015 (2015-04-09): 192.168.0.53 — port_scan src (attacker)
и nxdomain_burst src (victim). У обоих findings нет конкретной
пары, поэтому value пуст. Hint и рендер показывают finding_type,
чтобы аналитик знал, о какой находке речь.
"""
from __future__ import annotations

from collections import defaultdict

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding
from pcap_triage.contradictions.base import Contradiction, Fact


_PIVOT_CEILING = 0.90


def _describe(f: Fact) -> str:
    """
    Человекочитаемое описание факта для hint'а.

    Если value непустой — «finding_type → value» (что за находка, куда).
    Если value пуст (port_scan без цели, nxdomain_burst без домена) —
    только finding_type: роль всё равно информативна, конкретика — нет.
    """
    ftype = (f.evidence or {}).get("finding_type") or "?"
    if f.value:
        return f"{ftype} → {f.value}"
    return ftype


class VictimMakesAttackRule:
    name = "victim_makes_attack"
    severity_base = "critical"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        # Локальный импорт: правило не тянет весь facts-модуль на верхнем
        # уровне — проще тестировать изолированно.
        from pcap_triage.contradictions.facts import extract_attack_facts
        return extract_attack_facts(findings)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        by_subject: dict[str, dict[str, list[Fact]]] = defaultdict(
            lambda: {"victim_of": [], "attacker_of": []}
        )
        for f in facts:
            if f.predicate in ("victim_of", "attacker_of"):
                by_subject[f.subject][f.predicate].append(f)

        out: list[Contradiction] = []
        for subject, buckets in by_subject.items():
            # Self-loop: X атакует X — не pivot. Пустой value тоже
            # не считаем self-loop'ом: (unknown) ≠ subject.
            victims = [f for f in buckets["victim_of"] if f.value != subject]
            attackers = [
                f for f in buckets["attacker_of"] if f.value != subject
            ]
            if not victims or not attackers:
                continue

            # Самые уверенные представители каждого предиката.
            # Tie-breaker: факт с конкретным value информативнее
            # «роли без адресата» (port_scan, nxdomain_burst).
            v = max(victims, key=lambda f: (bool(f.value), f.confidence))
            a = max(attackers, key=lambda f: (bool(f.value), f.confidence))

            conf = round(min(v.confidence, a.confidence, _PIVOT_CEILING), 3)

            # Временной порядок: victim_of должен быть РАНЬШЕ attacker_of.
            # Если порядок обратный — повод для NAT/proxy-гипотезы.
            # ts == 0.0 трактуем как «timestamp отсутствует» (epoch
            # в реальном захвате не встречается).
            has_v_ts = v.ts > 0.0
            has_a_ts = a.ts > 0.0
            ts_ok: bool | None = None
            if has_v_ts and has_a_ts:
                ts_ok = v.ts <= a.ts

            v_desc = _describe(v)
            a_desc = _describe(a)

            if ts_ok is None:
                hint = (
                    f"{subject}: зафиксированы обе роли — victim "
                    f"({v_desc}) и attacker ({a_desc}). "
                    f"Timestamps недоступны, проверить хронологию по "
                    f"flows вручную: сначала атака на {subject}, "
                    f"потом атака с {subject} — классический pivot."
                )
            elif ts_ok:
                hint = (
                    f"{subject} сначала атакован ({v_desc}, ts={v.ts:.1f}), "
                    f"потом сам атакует ({a_desc}, ts={a.ts:.1f}). "
                    f"Классический pivot — проверить сессии {subject}."
                )
            else:
                hint = (
                    f"Порядок в захвате обратный: {subject} атакует "
                    f"({a_desc}, ts={a.ts:.1f}) РАНЬШЕ, чем атакован "
                    f"({v_desc}, ts={v.ts:.1f}). Возможен NAT/proxy "
                    f"или FP одной из эвристик."
                )

            out.append(Contradiction(
                rule=self.name,
                subject=subject,
                facts=[v, a],
                severity=self.severity_base,
                confidence=conf,
                likely_causes=[
                    "Хост скомпрометирован: сначала атакован, "
                    "потом сам атакует (pivot)",
                    "Authorized scanner в сети: "
                    "жертва одного скана — инициатор другого",
                    "NAT/proxy: одна IP скрывает несколько хостов",
                    "FP одной из эвристик",
                ],
                resolution_hint=hint,
            ))

        return out