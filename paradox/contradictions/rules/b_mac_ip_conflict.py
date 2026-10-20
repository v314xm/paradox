"""
Правило mac_ip_conflict (ARP spoof).

Случай: один IP отвечает двумя разными MAC за время захвата. В норме
IP ↔ MAC — 1:1 (в пределах сессии). Два MAC на один IP означает:
  - ARP spoof (MITM, атакующий перехватывает трафик жертвы),
  - IP conflict (два хоста с одним адресом — ошибка или клонирование VM),
  - DHCP lease change (новый хост получил освободившийся IP — легально).

Различаем по перекрытию временных окон:
  - окна пересекаются → оба MAC активны одновременно → spoof/конфликт
  - окна не пересекаются → смена MAC → скорее lease change

Severity:
  - critical: окна пересекаются, оба MAC имеют count ≥ 2 (устойчивые)
  - high:     окна пересекаются, один из MAC — единичный пакет
  - medium:   окна не пересекаются (lease change)

Confidence = min(conf_a, conf_b) × (1.0 overlap | 0.6 no overlap).
Потолок не нужен: оба факта уже взвешены по count, произведение
сверху ограничено 0.9.

Если MAC >2, правило срабатывает один раз на топ-2 по count.
Остальные MAC видны в JSON, если нужно детально разбирать —
следующая итерация, с группировкой по MAC-вендору.
"""
from __future__ import annotations

from collections import defaultdict

from paradox.config import Config
from paradox.models import CaptureState, Finding
from paradox.contradictions.base import Contradiction, Fact


class MacIpConflictRule:
    name = "mac_ip_conflict"
    severity_base = "critical"

    def extract_facts(
        self,
        state: CaptureState,
        findings: list[Finding],
        config: Config,
    ) -> list[Fact]:
        # Локальный импорт: правило не тянет весь facts-модуль.
        from paradox.contradictions.facts import extract_arp_facts
        return extract_arp_facts(state)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        by_ip: dict[str, list[Fact]] = defaultdict(list)
        for f in facts:
            if f.predicate == "has_mac":
                by_ip[f.subject].append(f)

        out: list[Contradiction] = []
        for ip, mac_facts in by_ip.items():
            unique_macs = {f.value for f in mac_facts}
            if len(unique_macs) < 2:
                continue

            # Топ-2 MAC по «устойчивости» (count из evidence,
            # затем confidence). Остальные игнорируем в этой итерации.
            def _sort_key(f: Fact) -> tuple[int, float]:
                return (f.evidence.get("count", 0), f.confidence)

            sorted_facts = sorted(mac_facts, key=_sort_key, reverse=True)
            seen: set[str] = set()
            top: list[Fact] = []
            for f in sorted_facts:
                if f.value not in seen:
                    seen.add(f.value)
                    top.append(f)
                if len(top) == 2:
                    break

            a, b = top

            a_first = a.evidence.get("first_ts", a.ts)
            a_last = a.evidence.get("last_ts", a.ts)
            b_first = b.evidence.get("first_ts", b.ts)
            b_last = b.evidence.get("last_ts", b.ts)

            overlap_start = max(a_first, b_first)
            overlap_end = min(a_last, b_last)
            overlap = overlap_end >= overlap_start

            a_count = a.evidence.get("count", 1)
            b_count = b.evidence.get("count", 1)
            both_stable = a_count >= 2 and b_count >= 2

            if overlap and both_stable:
                severity = "critical"
                conf_base = 1.0
            elif overlap:
                severity = "high"
                conf_base = 0.85
            else:
                severity = "medium"
                conf_base = 0.6

            conf = round(min(a.confidence, b.confidence) * conf_base, 3)

            if overlap:
                hint = (
                    f"{ip}: {a.value} и {b.value} активны одновременно "
                    f"(пересечение {overlap_start:.1f}–{overlap_end:.1f}). "
                    f"Классический ARP spoof / IP conflict — проверить "
                    f"MAC-flapping на коммутаторе и DHCP-логи."
                )
            else:
                hint = (
                    f"{ip}: {a.value} → {b.value} без пересечения окон "
                    f"({a_last:.1f} < {b_first:.1f}). Похоже на легальную "
                    f"смену MAC (DHCP lease change, новая машина получила "
                    f"IP). Проверить, что было в этот момент."
                )

            out.append(Contradiction(
                rule=self.name,
                subject=ip,
                facts=[a, b],
                severity=severity,
                confidence=conf,
                likely_causes=[
                    "ARP spoof / MITM: атакующий отвечает на ARP-запросы "
                    "от имени жертвы",
                    "IP conflict: два хоста настроены на один IP "
                    "(ошибка админа или клонирование VM)",
                    "DHCP lease change: новый хост получил освободившийся IP",
                    "MAC-flapping на коммутаторе (петля, HA-кластер)",
                ],
                resolution_hint=hint,
            ))

        return out