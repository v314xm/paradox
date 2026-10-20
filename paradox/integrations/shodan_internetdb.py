"""
Shodan InternetDB — бесплатный провайдер, без API-ключа.

GET https://internetdb.shodan.io/<ip>
Возвращает:
  {
    "ip": "8.8.8.8",
    "ports": [53, 443],
    "hostnames": ["dns.google"],
    "cpes": [],
    "vulns": ["CVE-2021-1234"],
    "tags": ["dns"]
  }

Особенности:
- 404 = IP не в базе Shodan. Это не ошибка — просто нет данных.
- Нет официального rate limit, но мы ограничиваем через TokenBucket
  в оркестраторе (по умолчанию 5 req/sec).
- Таймаут 10 сек по умолчанию.

Кэш-стратегия:
- Успешный ответ — TTL 7 дней.
- 404 — тоже кэшируем, но TTL 1 день (negative caching, чтобы
  не дёргать повторно, но обновлять часто).
"""
import json
import ssl
import time
import urllib.error
import urllib.request

import certifi

from paradox.integrations.base import EnrichmentResult

_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


class ShodanInternetDBEnricher:
    name = "shodan_internetdb"
    supports = ("ip",)
    ttl_days = 7
    ttl_days_negative = 1

    base_url = "https://internetdb.shodan.io"
    timeout = 10.0
    user_agent = "Paradox/0.6.0"

    @property
    def enabled(self) -> bool:
        """Shodan InternetDB — без ключа, всегда доступен."""
        return True

    def lookup(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        if ioc_type not in self.supports:
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                error=f"unsupported ioc_type: {ioc_type}",
                fetched_at=time.time(),
                ttl_days=self.ttl_days,
            )

        data, error = self._fetch(ioc)
        if error is not None:
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                error=error,
                fetched_at=time.time(),
                ttl_days=self.ttl_days,
            )

        # data is None → 404, нет в базе
        if data is None:
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                data={},
                fetched_at=time.time(),
                ttl_days=self.ttl_days_negative,
            )

        return EnrichmentResult(
            source=self.name, ioc=ioc, ioc_type=ioc_type,
            data=data,
            fetched_at=time.time(),
            ttl_days=self.ttl_days,
        )

    def _fetch(self, ip: str) -> tuple[dict | None, str | None]:
        """
        Вернуть (data, error).
        data=None + error=None — 404 (нет в базе).
        data=None + error="..." — сетевая ошибка или 5xx.
        """
        url = f"{self.base_url}/{ip}"
        req = urllib.request.Request(url, headers={
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=_SSL_CONTEXT,
            ) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")), None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, None
            return None, f"HTTP {e.code}"
        except urllib.error.URLError as e:
            return None, f"URLError: {e.reason}"
        except TimeoutError:
            return None, "timeout"
        except json.JSONDecodeError as e:
            return None, f"invalid json: {e}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"