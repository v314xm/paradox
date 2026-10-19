"""URLScan.io — сканы доменов и URL.

Search API без ключа (rate limit жёсткий). GET:
  https://urlscan.io/api/v1/search/?q=domain:example.com

Возвращает список последних сканов. Не по самому IOC — по запросу.
"""
import urllib.parse

from pcap_triage.integrations.base_enricher import BaseEnricher


class URLScanEnricher(BaseEnricher):
    name = "urlscan"
    supports = ("domain", "url")
    ttl_days = 1
    ttl_days_negative = 1
    base_url = "https://urlscan.io/api/v1/search"
    timeout = 12.0

    def _fetch(self, ioc: str, ioc_type: str) -> tuple[dict | None, str | None]:
        if ioc_type == "domain":
            query = f"domain:{ioc}"
        elif ioc_type == "url":
            query = f"page.url:{ioc}"
        else:
            return None, f"unsupported ioc_type: {ioc_type}"

        q = urllib.parse.quote(query)
        url = f"{self.base_url}/?q={q}&size=10"
        data, error = self._http_get_json(url)
        if error is None and isinstance(data, dict):
            if not data.get("results"):
                return None, None
        return data, error
