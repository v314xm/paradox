"""
Базовые контракты слоя обогащения (Threat Intel).

Enricher — Protocol: любой провайдер (Shodan, VT, AbuseIPDB)
реализует метод lookup(ioc) и возвращает EnrichmentResult
или None (если данных нет).

Инфраструктура (кэш, rate limit, оркестрация) — в отдельных модулях.
Провайдер не знает о кэше и rate limit — это забота оркестратора.
"""
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class EnrichmentResult:
    """
    Результат одного провайдера по одному IOC.
    """
    source: str
    ioc: str
    ioc_type: str = "ip"
    data: dict = field(default_factory=dict)
    fetched_at: float = 0.0
    ttl_days: int = 7
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class Enricher(Protocol):
    """
    Контракт провайдера Threat Intel.

    name — уникальное имя (используется как ключ кэша).
    supports — tuple типов IOC, которые принимает провайдер
               ("ip", "domain", "hash").
    ttl_days — дефолтный TTL кэша.
    """
    name: str
    supports: tuple[str, ...]
    ttl_days: int

    def lookup(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """
        Запросить данные по одному IOC.

        Не должен бросать исключения — при ошибке вернуть
        EnrichmentResult с error != None.
        """
        ...
