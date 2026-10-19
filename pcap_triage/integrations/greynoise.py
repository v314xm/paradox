"""GreyNoise Community API — шумит ли IP.

https://api.greynoise.io/v3/community/{ip}
Без ключа: 50 запросов/день. С ключом — больше.
"""
from pcap_triage.integrations.base_enricher import BaseEnricher


class GreyNoiseEnricher(BaseEnricher):
    name = "greynoise"
    supports = ("ip",)
    ttl_days = 1
    ttl_days_negative = 1
    base_url = "https://api.greynoise.io/v3/community"
    timeout = 10.0

    def _fetch(self, ioc: str, ioc_type: str) -> tuple[dict | None, str | None]:
        url = f"{self.base_url}/{ioc}"
        data, error = self._http_get_json(url)
        return self._resolve_not_found(data, error)
