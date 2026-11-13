"""Данные объяснения находки.

Explanation — то, что аналитик читает вместо списка голых полей:
что произошло, почему это важно, куда смотреть дальше и где детектор
может ошибаться. Строится в ядре, а не в GUI: один и тот же текст
идёт в модалку находки, в Markdown-отчёт и в JSON. Иначе появятся
три реализации, которые разойдутся — так уже было с internal/external
IP и с таблицами ролей до `taxonomy.py`.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Explanation:
    """Человеческое объяснение одной находки или противоречия."""

    # «Что произошло» — 1-2 предложения с конкретными значениями.
    headline: str
    # «Почему это важно» — этап атаки и что за ним обычно следует.
    why: str
    # «На что смотреть дальше» — конкретные шаги, а не «проверьте».
    next_steps: tuple[str, ...] = ()
    # Альтернативные интерпретации: где детектор может ошибаться.
    alternatives: tuple[str, ...] = ()
    # Как читать confidence этой конкретной находки.
    confidence_note: str = ""
    # То же объяснение без жаргона — режим «как новичку».
    beginner: str = ""

    # Машиночитаемый контекст: по ним GUI рисует чипы, отчёт — заголовки.
    phase: str = ""
    techniques: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "headline": self.headline,
            "why": self.why,
            "next_steps": list(self.next_steps),
            "alternatives": list(self.alternatives),
            "confidence_note": self.confidence_note,
            "beginner": self.beginner,
            "phase": self.phase,
            "techniques": list(self.techniques),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Explanation:
        """Собрать объяснение из JSON-отчёта.

        Нужно и GUI (окно объяснений читает готовый dict), и тестам на
        старые отчёты, где ключа `explanation` ещё нет.
        """
        return cls(
            headline=str(data.get("headline") or ""),
            why=str(data.get("why") or ""),
            next_steps=tuple(str(x) for x in data.get("next_steps") or ()),
            alternatives=tuple(str(x) for x in data.get("alternatives") or ()),
            confidence_note=str(data.get("confidence_note") or ""),
            beginner=str(data.get("beginner") or ""),
            phase=str(data.get("phase") or ""),
            techniques=tuple(str(x) for x in data.get("techniques") or ()),
        )

    def to_markdown(self) -> str:
        """Тот же текст для тикета, отчёта и кнопки «Копировать».

        Раздел `## Interpretation` в Markdown-отчёте будет собираться
        этим же методом — иначе копия и отчёт разойдутся.
        """
        lines = [f"**Что произошло.** {self.headline}", ""]
        if self.why:
            lines += [f"**Почему это важно.** {self.why}", ""]
        if self.next_steps:
            lines.append("**Что делать дальше.**")
            lines += [
                f"{index}. {step}"
                for index, step in enumerate(self.next_steps, 1)
            ]
            lines.append("")
        if self.alternatives:
            lines.append("**Альтернативные интерпретации.**")
            lines += [f"- {alt}" for alt in self.alternatives]
            lines.append("")
        if self.confidence_note:
            lines += [f"**Уверенность.** {self.confidence_note}", ""]
        if self.beginner:
            lines += [f"**Простыми словами.** {self.beginner}", ""]
        return "\n".join(lines).strip()


@dataclass(frozen=True)
class TypeSpec:
    """Шаблон объяснения для одного типа находки или правила.

    Тексты — шаблоны с подстановками `{key}`: key ищется сначала среди
    полей находки (`src`, `dst`, `port`, `value`, `conf`), затем среди
    скалярных значений `evidence`. Неизвестный ключ печатается как «—»,
    а не роняет отчёт.
    """

    headline: str
    why: str
    next_steps: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()
    beginner: str = ""
