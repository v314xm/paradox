"""
AbuseIPDB — репутация IP-адресов.

GET https://api.abuseipdb.com/api/v2/check
Заголовок Key: <API_KEY>
Query: ?ipAddress=8.8.8.8&maxAgeInDays=90

Ответ:
{
  "data": {
    "ipAddress": "8.8.8.8",
    "abuseConfidenceScore": 0,
    "countryCode": "US",
    "usageType": "Content Delivery Network",
    "isp": "Google LLC",
    "domain": "google.com",
    "totalReports": 0,
    "numDistinctUsers": 0,
    "lastReportedAt": null
  }
}

Free tier: 1000 запросов/день. Rate limit в оркестраторе.
Если ABUSEIPDB_API_KEY не установлен — провайдер отключается.
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import certifi

import certifi
import urllib.request

from pcap_triage.integrations.base import EnrichmentResult

# SSL-контекст с CA-бандлом certifi. Python на Windows не читает
# Windows Certificate Store, без этого HTTPS падает с
# CERTIFICATE_VERIFY_FAILED.
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


class AbuseIPDBEnricher:
    name = "abuseipdb"
    supports = ("ip",)
    ttl_days = 1  # abuse score меняется часто, TTL короткий

    base_url = "https://api.abuseipdb.com/api/v2/check"
    timeout = 10.0
    max_age_days = 90
    user_agent = "pcap-triage/0.6.0"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(
                source=self.name, ioc=ioc, ioc_type=ioc_type,
                error="ABUSEIPDB_API_KEY not set",
                fetched_at=time.time(),
                ttl_days=self.ttl_days,
            )

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

        return EnrichmentResult(
            source=self.name, ioc=ioc, ioc_type=ioc_type,
            data=data or {},
            fetched_at=time.time(),
            ttl_days=self.ttl_days,
        )

    def _fetch(self, ip: str) -> tuple[dict | None, str | None]:
        query = urllib.parse.urlencode({
            "ipAddress": ip,
            "maxAgeInDays": self.max_age_days,
        })
        url = f"{self.base_url}?{query}"
        req = urllib.request.Request(url, headers={
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        })

        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=_SSL_CONTEXT,
            ) as resp:
                raw = resp.read()
                payload = json.loads(raw.decode("utf-8"))
                return payload.get("data") or {}, None
        except urllib.error.HTTPError as e:
            if e.code == 429:
                return None, "rate limited (429)"
            if e.code == 401:
                return None, "unauthorized (401) — проверь ключ"
            if e.code == 422:
                return None, "invalid IP (422)"
            return None, f"HTTP {e.code}"
        except urllib.error.URLError as e:
            return None, f"URLError: {e.reason}"
        except TimeoutError:
            return None, "timeout"
        except json.JSONDecodeError as e:
            return None, f"invalid json: {e}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"