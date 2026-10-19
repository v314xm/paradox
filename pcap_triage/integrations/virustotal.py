"""VirusTotal API v3 — репутация IP, доменов, файлов.

Free tier: 4 запроса/мин, 500/день. Требует VIRUSTOTAL_API_KEY.

Покрывает:
  - IP: https://www.virustotal.com/api/v3/ip_addresses/{ip}
  - Домен: https://www.virustotal.com/api/v3/domains/{domain}
  - SHA256: https://www.virustotal.com/api/v3/files/{hash}
"""
import os

from pcap_triage.integrations.base_enricher import BaseEnricher


class VirusTotalEnricher(BaseEnricher):
    name = "virustotal"
    supports = ("ip", "domain", "hash")
    ttl_days = 1
    ttl_days_negative = 1
    base_url = "https://www.virustotal.com/api/v3"
    timeout = 15.0

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def disabled_reason(self) -> str:
        return "VIRUSTOTAL_API_KEY not set"

    def _fetch(self, ioc: str, ioc_type: str) -> tuple[dict | None, str | None]:
        endpoints = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
        }
        section = endpoints.get(ioc_type)
        if section is None:
            return None, f"unsupported ioc_type: {ioc_type}"

        url = f"{self.base_url}/{section}/{ioc}"
        data, error = self._http_get_json(
            url, headers={"x-apikey": self.api_key or ""},
        )
        return self._resolve_not_found(data, error)
