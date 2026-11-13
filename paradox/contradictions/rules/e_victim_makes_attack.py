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
from datetime import datetime

from paradox.config import Config
from paradox.contradictions.base import Contradiction, Fact
from paradox.i18n import L
from paradox.models import CaptureState, Finding

_PIVOT_CEILING = 0.90


def _clock(ts: float) -> str:
    """Время суток вместо epoch: hint читают глазами, а не парсер."""
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return f"{ts:.1f}"


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
        from paradox.contradictions.facts import extract_attack_facts
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
                hint = L(
                    (
                        f"{subject}: зафиксированы обе роли — victim "
                        f"({v_desc}) и attacker ({a_desc}). "
                        f"Timestamps недоступны, проверить хронологию по "
                        f"flows вручную: сначала атака на {subject}, "
                        f"потом атака с {subject} — классический pivot."
                    ),
                    (
                        f"{subject}: both roles are present — victim "
                        f"({v_desc}) and attacker ({a_desc}). "
                        f"Timestamps are unavailable; check the flow "
                        f"chronology by hand: first an attack on {subject}, "
                        f"then an attack from {subject} — classic pivot."
                    ),
                )
            elif ts_ok:
                hint = L(
                    (
                        f"{subject} сначала атакован "
                        f"({v_desc}, {_clock(v.ts)}), потом сам атакует "
                        f"({a_desc}, {_clock(a.ts)}). "
                        f"Классический pivot — проверить сессии {subject}."
                    ),
                    (
                        f"{subject} is attacked first "
                        f"({v_desc}, {_clock(v.ts)}), then attacks on its own "
                        f"({a_desc}, {_clock(a.ts)}). "
                        f"Classic pivot — check the sessions of {subject}."
                    ),
                )
            else:
                hint = L(
                    (
                        f"Порядок в захвате обратный: {subject} атакует "
                        f"({a_desc}, {_clock(a.ts)}) РАНЬШЕ, чем атакован "
                        f"({v_desc}, {_clock(v.ts)}). Возможен NAT/proxy "
                        f"или FP одной из эвристик."
                    ),
                    (
                        f"The order in the capture is reversed: {subject} "
                        f"attacks ({a_desc}, {_clock(a.ts)}) BEFORE it is "
                        f"attacked ({v_desc}, {_clock(v.ts)}). NAT/proxy or "
                        f"an FP of one of the heuristics is possible."
                    ),
                )

            out.append(Contradiction(
                rule=self.name,
                subject=subject,
                facts=[v, a],
                severity=self.severity_base,
                confidence=conf,
                likely_causes=[
                    L(
                        "Хост скомпрометирован: сначала атакован, "
                        "потом сам атакует",
                        "Host compromised: attacked first, then it attacks "
                        "on its own",
                    ),
                    L(
                        "Авторизованный сканер в сети: жертва одного скана — "
                        "инициатор другого",
                        "Authorised scanner in the network: the target of one "
                        "scan and the initiator of another",
                    ),
                    L(
                        "NAT или прокси: один адрес скрывает несколько хостов",
                        "NAT or a proxy: one address hides several hosts",
                    ),
                    L(
                        "Ошибка одной из эвристик",
                        "An error in one of the heuristics",
                    ),
                ],
                resolution_hint=hint,
            ))

        return out
