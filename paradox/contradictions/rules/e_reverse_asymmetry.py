"""
Правило reverse_asymmetry (эксфильтрация / односторонний канал).

Случай: в одной TCP/UDP сессии одна сторона передала в разы больше,
чем другая. Для нормального протокола (HTTP, TLS, SSH) обмен
примерно двусторонний. Если клиент залил 10 МБ и получил 50 КБ —
это выгрузка данных наружу.

Отличие от large_transfer:
  large_transfer:  absolute > 100 МБ в одну сторону. Топ-N сессий.
  reverse_asymmetry: ratio >= 10 при абсолютном >= 1 МБ. Пропорция
                     важна, а не абсолют. 5 МБ out + 50 КБ in
                     не попадёт в large_transfer, но попадёт сюда.

Severity:
  - high:   ratio >= 25. Почти односторонний канал — классика
            эксфильтрации или command-and-control.
  - medium: ratio >= 10. Подозрительно, но есть легитимные кейсы
            (upload больших файлов, streaming).
  - low:    сработало правило, но паттерн похож на bulk (шлюз/NAT).

Confidence = min(0.95, 0.5 + log10(ratio) × 0.15). Ограничено
сверху: без знания контекста (какой протокол, куда, от кого)
нельзя утверждать эксфильтрацию с уверенностью 1.0.

Отсеивается автоматически:
  - large_transfer уже ловит абсолютные эксфильтрации; правило
    не дублирует, но при ratio оно добавляет свою грань.
  - external ↔ external, internal ↔ internal — фильтр в facts.
  - сессии с total < 1 МБ — шум.

Агрегация по subject (0.7.0-wip, патч после CyberCampTask):
  Правило возвращает одну Contradiction на subject, не на каждую
  сессию. Иначе шлюз (192.168.1.1), через который NAT-ится трафик
  клиентов, даёт 9 «эксфильтраций» за один pcap. Для шлюза это
  нормальный паттерн — severity понижается до low, confidence × 0.7.
"""
from __future__ import annotations

import math

from paradox.config import Config
from paradox.contradictions.base import Contradiction, Fact
from paradox.i18n import L
from paradox.models import CaptureState, Finding


def _bytes(value) -> str:
    """«280 271 306 Б» вместо «280271306 Б» — подсказку читают глазами."""
    if not isinstance(value, int):
        return f"{value}" + L(" Б", " B")
    return f"{value:,}".replace(",", " ") + L(" Б", " B")


class ReverseAsymmetryRule:
    name = "reverse_asymmetry"
    severity_base = "medium"

    # Порог, после которого считаем паттерн «bulk» (шлюз/CDN-прокси),
    # а не одиночную эксфильтрацию. 5 — эмпирически: реальный
    # эксфильтрационный канал редко бывает параллельным, а шлюз
    # имеет десятки асимметричных сессий от клиентов.
    _BULK_THRESHOLD = 5

    def extract_facts(
            self,
            state: CaptureState,
            findings: list[Finding],
            config: Config,
    ) -> list[Fact]:
        self._min_ratio = config.reverse_asymmetry_min_ratio
        self._high_ratio = config.reverse_asymmetry_high_ratio
        from paradox.contradictions.facts import extract_asymmetry_facts
        return extract_asymmetry_facts(state, config)

    def find_contradictions(
        self, facts: list[Fact],
    ) -> list[Contradiction]:
        _min_ratio = getattr(self, "_min_ratio", None)
        _high_ratio = getattr(self, "_high_ratio", None)
        if _min_ratio is None or _high_ratio is None:
            from paradox.config import Config
            _cfg = Config()
            if _min_ratio is None:
                _min_ratio = _cfg.reverse_asymmetry_min_ratio
            if _high_ratio is None:
                _high_ratio = _cfg.reverse_asymmetry_high_ratio

        # 1. Фильтр по ratio + группировка по subject.
        by_subject: dict[str, list[Fact]] = {}
        for f in facts:
            if f.predicate != "session_asymmetry":
                continue
            ratio = f.evidence.get("ratio", 1.0)
            if ratio < _min_ratio:
                continue
            by_subject.setdefault(f.subject, []).append(f)

        out: list[Contradiction] = []
        for subject, subj_facts in by_subject.items():
            # 2. Топ-факт по severity, потом по ratio, потом по total.
            #    При равной severity — больший ratio важнее.
            def _sort_key(f: Fact) -> tuple:
                r = f.evidence.get("ratio", 0.0)
                # inf нельзя сравнивать с числами — заменяем на 1e9.
                r_key = 1e9 if r == float("inf") else r
                sev = "high" if r_key >= _high_ratio else "medium"
                return (
                    0 if sev == "high" else 1,
                    -r_key,
                    -f.evidence.get("total_bytes", 0),
                )

            subj_facts.sort(key=_sort_key)
            best = subj_facts[0]

            count = len(subj_facts)
            total_bytes_all = sum(
                f.evidence.get("total_bytes", 0) for f in subj_facts
            )

            ratio = best.evidence.get("ratio", 1.0)
            base_sev = "high" if ratio >= _high_ratio else "medium"

            # 3. Понижение severity для bulk-паттерна.
            if count >= self._BULK_THRESHOLD:
                severity = "low"
            elif count >= 3:
                severity = "medium" if base_sev == "high" else "low"
            else:
                severity = base_sev

            # 4. Confidence — по best. Дополнительно снижаем при bulk,
            #    потому что «много сессий с одного IP» — скорее шлюз.
            if math.isinf(ratio):
                base_conf = 0.95
            else:
                base_conf = min(0.95, 0.5 + math.log10(ratio) * 0.15)
            if count >= self._BULK_THRESHOLD:
                base_conf *= 0.7
            conf = round(base_conf, 3)

            # 5. Hint — разный для bulk и одиночной сессии.
            bytes_out = best.evidence.get("bytes_out", 0)
            bytes_in = best.evidence.get("bytes_in", 0)
            external_ip = best.evidence.get("external_ip", "?")
            external_port = best.evidence.get("external_port")
            proto = best.evidence.get("proto", "?")
            outbound = bytes_out > bytes_in
            # Подсказку читают глазами: направление — по-русски.
            direction = (
                L("наружу", "outbound") if outbound else L("внутрь", "inbound")
            )

            if math.isinf(ratio):
                ratio_str = L("∞ (односторонний)", "∞ (one-way)")
            else:
                ratio_str = f"{ratio:.1f}:1"

            if count >= self._BULK_THRESHOLD:
                bulk = (
                    L("выгрузка", "outbound transfer") if outbound
                    else L("загрузка", "inbound transfer")
                )
                hint = L(
                    (
                        f"{subject}: асимметричных сессий — {count}, "
                        f"суммарно {_bytes(total_bytes_all)}. Топ-1: "
                        f"{external_ip}:{external_port} ({proto}), "
                        f"ratio {ratio_str}, направление {direction}. "
                        f"Похоже на шлюз / NAT / CDN-прокси — не одиночная "
                        f"сессия. Если хост НЕ шлюз, это массовая {bulk}."
                    ),
                    (
                        f"{subject}: asymmetric sessions — {count}, "
                        f"{_bytes(total_bytes_all)} in total. Top-1: "
                        f"{external_ip}:{external_port} ({proto}), "
                        f"ratio {ratio_str}, direction {direction}. "
                        f"Looks like a gateway / NAT / CDN proxy — not a "
                        f"single session. If the host is NOT a gateway, this "
                        f"is bulk {bulk}."
                    ),
                )
            else:
                hint = L(
                    (
                        f"{subject}: асимметричных сессий — {count}. "
                        f"Топ-1: {external_ip}:{external_port} ({proto}), "
                        f"out={_bytes(bytes_out)}, in={_bytes(bytes_in)}, "
                        f"ratio {ratio_str}, направление {direction}. "
                        f"Проверить протокол и назначение."
                    ),
                    (
                        f"{subject}: asymmetric sessions — {count}. "
                        f"Top-1: {external_ip}:{external_port} ({proto}), "
                        f"out={_bytes(bytes_out)}, in={_bytes(bytes_in)}, "
                        f"ratio {ratio_str}, direction {direction}. "
                        f"Check the protocol and the purpose of the "
                        f"connection."
                    ),
                )

            out.append(Contradiction(
                rule=self.name,
                subject=subject,
                facts=[best],
                severity=severity,
                confidence=conf,
                likely_causes=self._causes(outbound),
                resolution_hint=hint,
            ))

        out.sort(key=lambda c: (-c.priority, -c.confidence, c.subject))
        return out

    @staticmethod
    def _causes(outbound: bool) -> list[str]:
        """Причины в порядке релевантности: перекос бывает в обе стороны.

        Первым идёт то, что соответствует направлению перекоса, иначе
        для сессии «скачали 33 МБ» первым объяснением стояла выгрузка.
        """
        if outbound:
            return [
                L(
                    "Выгрузка данных наружу: отдано в разы больше, "
                    "чем получено",
                    "Data sent outbound: many times more sent than received",
                ),
                L(
                    "Легитимная отправка: бэкап, выгрузка в облако, "
                    "видеоконференция",
                    "Legitimate sending: backup, cloud upload, video "
                    "conference",
                ),
                L(
                    "Туннель с короткими ответами-подтверждениями",
                    "A tunnel with short acknowledgement replies",
                ),
                L(
                    "Шлюз / NAT / CDN-прокси: агрегат трафика клиентов",
                    "Gateway / NAT / CDN proxy: aggregate client traffic",
                ),
                L(
                    "Односторонний захват: вторая сторона не зеркалится",
                    "One-sided capture: the other side is not mirrored",
                ),
            ]
        return [
            L(
                "Загрузка большого файла: обновление, образ диска, медиа",
                "Large file download: an update, a disk image, media",
            ),
            L(
                "Доставка инструмента: скачивание payload'а",
                "Tool delivery: downloading a payload",
            ),
            L(
                "Легитимный стриминг или видеоконференция",
                "Legitimate streaming or a video conference",
            ),
            L(
                "Шлюз / NAT / CDN-прокси: агрегат трафика клиентов",
                "Gateway / NAT / CDN proxy: aggregate client traffic",
            ),
            L(
                "Односторонний захват: вторая сторона не зеркалится",
                "One-sided capture: the other side is not mirrored",
            ),
        ]
