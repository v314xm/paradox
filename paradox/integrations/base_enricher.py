"""Базовый класс для enrichment-провайдеров.

Даёт общий HTTP-клиент, обработку 401/403/404/429/5xx, таймауты,
единый формат EnrichmentResult. Новые провайдеры наследуются от
BaseEnricher и реализуют только `_fetch(ioc, ioc_type)`.

Shodan и AbuseIPDB исторически не наследуются — они в проде, их
не трогаем. Все новые — только через BaseEnricher.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import certifi

from paradox.integrations.base import EnrichmentResult


# Общий SSL-контекст с CA-бандлом certifi. Python на Windows не
# читает Windows Certificate Store, поэтому без этого все HTTPS-
# запросы падают с CERTIFICATE_VERIFY_FAILED.
_SSL_CONTEXT: ssl.SSLContext | None = None


def _get_ssl_context() -> ssl.SSLContext:
    global _SSL_CONTEXT
    if _SSL_CONTEXT is None:
        _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
    return _SSL_CONTEXT


class BaseEnricher:
    #: машинное имя (совпадает с ключом Config.enrichment_enabled_providers)
    name: str = ""
    #: какие типы IOC поддерживаются: ("ip",), ("ip", "domain"), ...
    supports: tuple[str, ...] = ()
    #: TTL успешного ответа в днях
    ttl_days: int = 7
    #: TTL «пусто/404» — negative caching
    ttl_days_negative: int = 1
    timeout: float = 10.0
    user_agent: str = "Paradox/0.9.0"

    # -- API для оркестратора ---------------------------------------------

    @property
    def enabled(self) -> bool:
        """Провайдер активен. По умолчанию — да.

        Провайдеры с ключом переопределяют: `return bool(self.api_key)`.
        """
        return True

    def disabled_reason(self) -> str:
        """Почему выключен. По умолчанию — generic."""
        return "disabled"

    def lookup(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        if ioc_type not in self.supports:
            return self._error(ioc, ioc_type, f"unsupported ioc_type: {ioc_type}")
        if not self.enabled:
            return self._error(ioc, ioc_type, self.disabled_reason())

        data, error = self._fetch(ioc, ioc_type)
        if error is not None:
            return self._error(ioc, ioc_type, error)
        if data is None:
            # 404 — нет в базе. Не ошибка, просто нет данных.
            return self._ok(ioc, ioc_type, {}, ttl=self.ttl_days_negative)
        return self._ok(ioc, ioc_type, data, ttl=self.ttl_days)

    # -- переопределяется в наследниках -----------------------------------

    def _fetch(self, ioc: str, ioc_type: str) -> tuple[dict | None, str | None]:
        """Вернуть (data, error).

        data=None + error=None  → 404, нет в базе.
        data=None + error="..." → сетевая/HTTP ошибка.
        """
        raise NotImplementedError

    # -- helpers для наследников ------------------------------------------

    def _http_get_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict | None, str | None]:
        """GET → JSON с унифицированной обработкой ошибок."""
        h = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        if headers:
            h.update(headers)

        req = urllib.request.Request(url, headers=h)
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=_get_ssl_context(),
            ) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")), None
        except urllib.error.HTTPError as e:
            return None, self._http_error_message(e)
        except urllib.error.URLError as e:
            return None, f"URLError: {e.reason}"
        except TimeoutError:
            return None, "timeout"
        except json.JSONDecodeError as e:
            return None, f"invalid json: {e}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"

    def _http_post_json(
        self,
        url: str,
        *,
        form: dict[str, str] | None = None,
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict | None, str | None]:
        """POST с унифицированной обработкой ошибок.

        form  — application/x-www-form-urlencoded (abuse.ch)
        json_body — application/json (threatfox)
        """
        h = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        if headers:
            h.update(headers)

        body: bytes
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            h["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode("utf-8")
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = b""

        req = urllib.request.Request(url, data=body, headers=h, method="POST")
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=_get_ssl_context(),
            ) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")), None
        except urllib.error.HTTPError as e:
            return None, self._http_error_message(e)
        except urllib.error.URLError as e:
            return None, f"URLError: {e.reason}"
        except TimeoutError:
            return None, "timeout"
        except json.JSONDecodeError as e:
            return None, f"invalid json: {e}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"

    @staticmethod
    def _http_error_message(e: urllib.error.HTTPError) -> str:
        code = e.code
        if code == 401:
            return "unauthorized (401) — проверь ключ"
        if code == 403:
            return "forbidden (403) — нет доступа к API"
        if code == 404:
            # Спецсигнал для lookup(): data=None + error=None → нет в базе.
            return "__not_found__"
        if code == 429:
            return "rate limited (429)"
        if 500 <= code < 600:
            return f"server error ({code})"
        return f"HTTP {code}"

    def _ok(self, ioc, ioc_type, data, ttl: int | None = None) -> EnrichmentResult:
        return EnrichmentResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
            fetched_at=time.time(),
            ttl_days=ttl if ttl is not None else self.ttl_days,
        )

    def _error(self, ioc, ioc_type, error: str) -> EnrichmentResult:
        return EnrichmentResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            error=error,
            fetched_at=time.time(),
            ttl_days=self.ttl_days,
        )

    def _resolve_not_found(
        self, data, error,
    ) -> tuple[dict | None, str | None]:
        """Превратить спецсигнал __not_found__ в пару (None, None)."""
        if error == "__not_found__":
            return None, None
        return data, error
