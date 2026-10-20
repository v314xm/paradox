"""AlienVault OTX — открытый threat intel, без ключа.

https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general

Секции: IPv4, domain, file (для хэшей).
"""
from paradox.integrations.base_enricher import BaseEnricher


class AlienVaultOTXEnricher(BaseEnricher):
    name = "alienvault_otx"
    supports = ("ip", "domain", "hash")
    ttl_days = 3
    ttl_days_negative = 1
    base_url = "https://otx.alienvault.com/api/v1/indicators"
    timeout = 12.0

    def _fetch(self, ioc: str, ioc_type: str) -> tuple[dict | None, str | None]:
        section = {"ip": "IPv4", "domain": "domain", "hash": "file"}.get(ioc_type)
        if section is None:
            return None, f"unsupported ioc_type: {ioc_type}"
        url = f"{self.base_url}/{section}/{ioc}/general"
        return self._http_get_json(url)
