"""
Оркестратор обогащения.

Собирает уникальные IOC из findings, зовёт провайдеров (с кэшем
и rate limit), возвращает результаты.

Поддерживает и dict-и, и Finding — через универсальные helpers.
Приватные IP (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16,
224/4, 239/4) не собираются — Shodan про них ничего не знает.
"""
from paradox.config import Config
from paradox.integrations.base import EnrichmentResult
from paradox.integrations.cache import EnrichmentCache
from paradox.integrations.rate_limit import TokenBucket

DEFAULT_RATE_LIMIT_PER_SEC = 5.0


class EnricherOrchestrator:
    """
    Управляет обогащением: кэш + rate limit + вызовы провайдеров.

    providers — список Enricher (реализаций Protocol).
    cache — EnrichmentCache.
    config — Config с enrichment_* параметрами.
    """
    def __init__(
        self,
        providers: list,
        cache: EnrichmentCache,
        config: Config,
    ):
        self.providers = providers
        self.cache = cache
        self.config = config

        self._buckets: dict[str, TokenBucket] = {
            p.name: TokenBucket(
                capacity=int(DEFAULT_RATE_LIMIT_PER_SEC) or 1,
                refill_per_sec=DEFAULT_RATE_LIMIT_PER_SEC,
            )
            for p in providers
        }

        self.stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "rate_limited": 0,
            "provider_calls": 0,
            # errors разбит по категориям — сетевые / авторизация /
            # сервер 5xx / провайдер вернул 429. Сумма = общее число
            # ошибок (errors). rate_limited (локальный token bucket)
            # считается отдельно и в errors НЕ входит.
            "errors": 0,
            "errors_network": 0,
            "errors_auth": 0,
            "errors_server": 0,
            "errors_rate_limited": 0,
            # Провайдер не вызван: выключен в настройках, не поддерживает
            # тип, или у него нет ключа (enabled=False).
            "skipped_disabled": 0,
            "skipped_unsupported": 0,
        }

    def enrich(
        self,
        iocs: list[tuple[str, str]],
    ) -> dict[tuple[str, str], list[EnrichmentResult]]:
        """
        Обогатить список IOC.

        iocs — список (ioc_type, ioc_value), например
               [("ip", "8.8.8.8"), ("domain", "example.com")].
               Дубликаты удаляются внутри.

        Возвращает dict {(ioc_type, ioc): [EnrichmentResult, ...]}.
        """
        unique = list({(t, v) for (t, v) in iocs})
        unique = unique[: self.config.enrichment_max_iocs]

        out: dict[tuple[str, str], list[EnrichmentResult]] = {}
        enabled = self.config.enrichment_enabled_providers

        for ioc_type, ioc in unique:
            results: list[EnrichmentResult] = []

            for provider in self.providers:
                if provider.name not in enabled:
                    self.stats["skipped_disabled"] += 1
                    continue
                if ioc_type not in provider.supports:
                    self.stats["skipped_unsupported"] += 1
                    continue
                # Провайдер без ключа/без конфигурации. Не дёргаем —
                # это не ошибка, просто нечего запрашивать.
                if not getattr(provider, "enabled", True):
                    self.stats["skipped_disabled"] += 1
                    continue

                cached = self.cache.get(provider.name, ioc)
                if cached is not None:
                    self.stats["cache_hits"] += 1
                    results.append(cached)
                    continue

                self.stats["cache_misses"] += 1

                bucket = self._buckets[provider.name]
                if not bucket.try_acquire():
                    self.stats["rate_limited"] += 1
                    continue

                self.stats["provider_calls"] += 1
                result = provider.lookup(ioc, ioc_type)

                if result.ok:
                    self.cache.put(result)
                else:
                    self.stats["errors"] += 1
                    self._classify_error(result.error or "")

                results.append(result)

            if results:
                out[(ioc_type, ioc)] = results

        return out

    def _classify_error(self, error: str) -> None:
        """Разложить ошибку по категориям.

        Инвариант: errors_auth + errors_network + errors_server +
        errors_rate_limited == errors. Локальный rate_limited
        (наш token bucket) в errors НЕ входит — считается отдельно.
        """
        e = error.lower()
        if ("401" in e or "403" in e or "unauthorized" in e
                or "forbidden" in e or "key" in e and "not set" in e):
            self.stats["errors_auth"] += 1
        elif "429" in e or "rate limited" in e:
            # Провайдер вернул 429 — его rate limit, не наш.
            self.stats["errors_rate_limited"] += 1
        elif ("500" in e or "502" in e or "503" in e or "504" in e
              or "server error" in e):
            self.stats["errors_server"] += 1
        else:
            self.stats["errors_network"] += 1

    def close(self) -> None:
        self.cache.close()


from paradox.net_utils import is_private_ip as _is_private_ip


def collect_iocs_from_findings(findings) -> list[tuple[str, str]]:
    """
    Вытащить IP и домены из findings для обогащения.
    Работает и с dict, и с Finding.

    Источники:
    - evidence["dst_ip"], evidence["src_ip"], evidence["ip"] — IP.
      Приватные IP пропускаются.
    - evidence["base_domain"], ["sni"], ["host"], ["domain"] — домены.
    - value для findings типа dga_domain, typosquatting и т.п.
    """
    out: list[tuple[str, str]] = []
    ip_fields = {"dst_ip", "src_ip", "ip"}
    domain_fields = {"base_domain", "sni", "host", "domain"}
    domain_value_types = {"dga_domain", "typosquatting",
                          "cloud_tunnel_domain", "ip_check_service"}

    for f in findings:
        if isinstance(f, dict):
            ev = f.get("evidence") or {}
            f_type = f.get("type") or ""
            f_value = f.get("value") or ""
        else:
            ev = f.evidence or {}
            f_type = f.type
            f_value = f.value

        for field in ip_fields:
            val = ev.get(field)
            if isinstance(val, str) and val and not _is_private_ip(val):
                out.append(("ip", val))

        for field in domain_fields:
            val = ev.get(field)
            if isinstance(val, str) and val:
                out.append(("domain", val))

        if f_type in domain_value_types and f_value:
            v = f_value.strip()
            if v and " " not in v and ":" not in v:
                out.append(("domain", v))

    return list({(t, v) for (t, v) in out})
