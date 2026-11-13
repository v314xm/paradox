"""
Правило ja3_ua_mismatch (спуфинг TLS-стека / UA).

Случай: один клиент (src_ip) ходит с TLS-стеком одного семейства
и UA другого. Chrome не может использовать python-requests.
python-requests не может выдавать себя за Chrome по JA3, но может
подделать UA — именно это правило и ловит.

Норма:
  - Chrome-JA3 + Chrome-UA — норм.
  - python-requests-JA3 + python-requests-UA — норм (скрипт).
  - browser-JA3 + tool-UA и наоборот — уже подозрительно, но
    low/medium.

Подозрительно:
  - tool-JA3 (python/go/curl) + browser-UA (Chrome/Firefox/Edge) →
    скрипт мимикрирует под браузер. High.
  - malware-JA3 (Cobalt Strike, Tor, Dridex) + любой UA → критично,
    JA3 уже палево. Critical. (Дублирует ja3_malware detector, но
    в contradiction-слое это отдельный сигнал: JA3 malware в
    сочетании с именем «я — браузер» — попытка спрятаться.)
  - browser-JA3 + tool-UA → medium, странная пара, но не атака.

Confidence:
  - critical: 0.85
  - high:     0.75
  - medium:   0.6

Правило НЕ дублирует ja3_malware detector: там finding на любой
JA3 из списка. Здесь — только при несовместимости с UA.
"""
from __future__ import annotations

from collections import defaultdict

from paradox.config import Config
from paradox.contradictions.base import Contradiction, Fact
from paradox.i18n import L
from paradox.models import CaptureState, Finding

_BROWSER_FAMILIES = frozenset({"chrome", "firefox", "edge", "safari"})
# "tool" — общая категория из _classify_ja3 (все известные
# инструменты без уточнения). Остальные — конкретные семейства,
# если в будущем начнём различать их по конфигу.
_TOOL_FAMILIES = frozenset({"python", "go", "curl", "wget", "tool"})


class Ja3UaMismatchRule:
    name = "ja3_ua_mismatch"
    severity_base = "high"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        from paradox.contradictions.facts import extract_ja3_ua_facts
        return extract_ja3_ua_facts(state, config)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        by_subject: dict[str, dict[str, list[Fact]]] = defaultdict(
            lambda: {"uses_ja3": [], "uses_ua": []}
        )
        for f in facts:
            if f.predicate in ("uses_ja3", "uses_ua"):
                by_subject[f.subject][f.predicate].append(f)

        out: list[Contradiction] = []
        for src, buckets in by_subject.items():
            if not buckets["uses_ja3"] or not buckets["uses_ua"]:
                continue

            # Считаем уникальные пары (family_ja3, family_ua)
            seen_pairs: set[tuple[str, str]] = set()

            for j_fact in buckets["uses_ja3"]:
                for u_fact in buckets["uses_ua"]:
                    j_fam = j_fact.evidence.get("family", "unknown")
                    u_fam = u_fact.evidence.get("family", "unknown")

                    severity, reason, conf = self._classify(j_fam, u_fam)
                    if severity is None:
                        continue

                    # Один contradiction на пару семейств для src —
                    # не плодим N×M на каждый UA в сессии.
                    pair = (j_fam, u_fam)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)

                    out.append(Contradiction(
                        rule=self.name,
                        subject=src,
                        facts=[j_fact, u_fact],
                        severity=severity,
                        confidence=conf,
                        likely_causes=[
                            L(
                                "Скрипт (C2, сканер) подделывает User-Agent "
                                "под браузер, но TLS-стек остался скриптовый",
                                "A script (C2, scanner) spoofs the User-Agent "
                                "as a browser, but the TLS stack stays that "
                                "of a script",
                            ),
                            L(
                                "Автоматизация/тест через реальный браузерный "
                                "стек — редко, но бывает",
                                "Automation or a test through a real browser "
                                "stack — rare, but it happens",
                            ),
                            L(
                                "Корпоративный прокси переписывает UA на лету",
                                "A corporate proxy rewrites the UA on the fly",
                            ),
                            L(
                                "FP: UA из http_objects с другого соединения "
                                "того же хоста",
                                "FP: the UA comes from http_objects of "
                                "another connection of the same host",
                            ),
                        ],
                        resolution_hint=reason,
                    ))

        return out

    def _classify(
        self, j_fam: str, u_fam: str,
    ) -> tuple[str | None, str, float]:
        """→ (severity | None, hint, confidence)."""
        if j_fam == "malware":
            return (
                "critical",
                L(
                    (
                        f"Клиент с JA3 семейства `{j_fam}` (malware) при этом "
                        f"с UA семейства `{u_fam}`. TLS-стек уже палево — "
                        f"проверить сессии клиента."
                    ),
                    (
                        f"Client with a JA3 of family `{j_fam}` (malware) but "
                        f"a UA of family `{u_fam}`. The TLS stack alone is a "
                        f"red flag — check the client's sessions."
                    ),
                ),
                0.85,
            )
        if j_fam in _TOOL_FAMILIES and u_fam in _BROWSER_FAMILIES:
            return (
                "high",
                L(
                    (
                        f"JA3=`{j_fam}` (скрипт) + UA=`{u_fam}` (браузер). "
                        f"Классическая мимикрия: клиент выдаёт себя за "
                        f"браузер, но TLS-стек — от скрипта. Проверить, что "
                        f"за скрипт и куда ходит."
                    ),
                    (
                        f"JA3=`{j_fam}` (script) + UA=`{u_fam}` (browser). "
                        f"Classic mimicry: the client poses as a browser, but "
                        f"the TLS stack belongs to a script. Check which "
                        f"script it is and where it connects."
                    ),
                ),
                0.75,
            )
        if j_fam in _BROWSER_FAMILIES and u_fam in _TOOL_FAMILIES:
            return (
                "medium",
                L(
                    (
                        f"JA3=`{j_fam}` (браузер) + UA=`{u_fam}` (скрипт). "
                        f"Странная пара: браузерный TLS-стек, но скриптовый "
                        f"UA. Возможно, автоматизация через headless-browser "
                        f"или FP парсера."
                    ),
                    (
                        f"JA3=`{j_fam}` (browser) + UA=`{u_fam}` (script). "
                        f"Odd pair: a browser TLS stack with a script UA. "
                        f"Possibly automation through a headless browser or a "
                        f"parser FP."
                    ),
                ),
                0.6,
            )
        return None, "", 0.0
