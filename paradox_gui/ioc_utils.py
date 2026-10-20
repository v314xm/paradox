"""Определение типа IOC и ссылки на публичные страницы провайдеров."""
from __future__ import annotations

import ipaddress
import re

_HASH_HEX = re.compile(r"^[a-fA-F0-9]{32,64}$")
_URL = re.compile(r"^https?://", re.IGNORECASE)


def detect_ioc_type(value: str) -> str | None:
    """Вернуть 'ip' | 'domain' | 'url' | 'hash' | None.

    Порядок проверок: url → ip → hash → domain.
    """
    v = value.strip()
    if not v:
        return None
    if _URL.match(v):
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HASH_HEX.match(v):
        return "hash"
    # Домен — грубая проверка: хотя бы одна точка, нет пробелов
    if "." in v and " " not in v and "/" not in v:
        return "domain"
    return None


#: Провайдер → шаблон публичной страницы по IOC.
PROVIDER_LINKS: dict[str, dict[str, str]] = {
    "shodan_internetdb": {
        "ip": "https://www.shodan.io/host/{v}",
    },
    "abuseipdb": {
        "ip": "https://www.abuseipdb.com/check/{v}",
    },
    "virustotal": {
        "ip": "https://www.virustotal.com/gui/ip-address/{v}",
        "domain": "https://www.virustotal.com/gui/domain/{v}",
        "hash": "https://www.virustotal.com/gui/file/{v}",
    },
    "greynoise": {
        "ip": "https://viz.greynoise.io/ip/{v}",
    },
    "alienvault_otx": {
        "ip": "https://otx.alienvault.com/indicator/ip/{v}",
        "domain": "https://otx.alienvault.com/indicator/domain/{v}",
        "hash": "https://otx.alienvault.com/indicator/file/{v}",
    },
    "urlscan": {
        "domain": "https://urlscan.io/domain/{v}",
        "url": "https://urlscan.io/search/#{v}",
    },
    "urlhaus": {
        "domain": "https://urlhaus.abuse.ch/host/{v}",
        "url": "https://urlhaus.abuse.ch/browse/#{v}",
    },
    "malwarebazaar": {
        "hash": "https://bazaar.abuse.ch/sample/{v}",
    },
    "threatfox": {
        "ip": "https://threatfox.abuse.ch/browse/?search={v}",
        "domain": "https://threatfox.abuse.ch/browse/?search={v}",
        "hash": "https://threatfox.abuse.ch/browse/?search={v}",
    },
}


def provider_link(provider_name: str, ioc: str, ioc_type: str) -> str | None:
    tpls = PROVIDER_LINKS.get(provider_name)
    if not tpls:
        return None
    tpl = tpls.get(ioc_type)
    if not tpl:
        return None
    return tpl.format(v=ioc)
