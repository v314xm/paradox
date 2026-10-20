"""URLhaus (abuse.ch) — malware URLs.

Требует Auth-Key (заголовок Auth-Key). Бесплатно, регистрация:
https://auth.abuse.ch/

POST form:
  host=example.com    → /v1/host/
  url=https://...     → /v1/url/
"""
import os

from paradox.integrations.base_enricher import BaseEnricher


class URLhausEnricher(BaseEnricher):
    name = "urlhaus"
    supports = ("domain", "url")
    ttl_days = 1
    ttl_days_negative = 1
    base_url = "https://urlhaus-api.abuse.ch/v1"
    timeout = 10.0

    def __init__(self, auth_key: str | None = None) -> None:
        self.auth_key = auth_key or os.environ.get("ABUSECH_AUTH_KEY")

    @property
    def enabled(self) -> bool:
        return bool(self.auth_key)

    def disabled_reason(self) -> str:
        return "ABUSECH_AUTH_KEY not set"

    def _fetch(self, ioc: str, ioc_type: str) -> tuple[dict | None, str | None]:
        if ioc_type == "domain":
            url = f"{self.base_url}/host/"
            form = {"host": ioc}
        elif ioc_type == "url":
            url = f"{self.base_url}/url/"
            form = {"url": ioc}
        else:
            return None, f"unsupported ioc_type: {ioc_type}"

        data, error = self._http_post_json(
            url, form=form, headers={"Auth-Key": self.auth_key or ""},
        )
        # URLhaus: query_status == "no_results" — нет данных.
        if error is None and isinstance(data, dict):
            status = data.get("query_status")
            if status == "no_results":
                return None, None
        return data, error
