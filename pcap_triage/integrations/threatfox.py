"""ThreatFox (abuse.ch) — IOC от сообщества.

Требует Auth-Key. POST JSON: {"query": "search_ioc", "search_term": "..."}
"""
import os

from pcap_triage.integrations.base_enricher import BaseEnricher


class ThreatFoxEnricher(BaseEnricher):
    name = "threatfox"
    supports = ("ip", "domain", "hash")
    ttl_days = 1
    ttl_days_negative = 1
    base_url = "https://threatfox-api.abuse.ch/api/v1/"
    timeout = 10.0

    def __init__(self, auth_key: str | None = None) -> None:
        self.auth_key = auth_key or os.environ.get("ABUSECH_AUTH_KEY")

    @property
    def enabled(self) -> bool:
        return bool(self.auth_key)

    def disabled_reason(self) -> str:
        return "ABUSECH_AUTH_KEY not set"

    def _fetch(self, ioc: str, ioc_type: str) -> tuple[dict | None, str | None]:
        if ioc_type not in self.supports:
            return None, f"unsupported ioc_type: {ioc_type}"
        data, error = self._http_post_json(
            self.base_url,
            json_body={"query": "search_ioc", "search_term": ioc},
            headers={"Auth-Key": self.auth_key or ""},
        )
        if error is None and isinstance(data, dict):
            status = data.get("query_status")
            if status in ("no_result", "illegal_search_term"):
                return None, None
        return data, error
