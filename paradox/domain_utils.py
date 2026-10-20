"""
Domain parsing helpers: единый источник правды для SLD/TLD.

v0.9.0: поддержка двухуровневых публичных суффиксов (co.uk, com.au,
co.jp, com.br, ...). Полный Public Suffix List (PSL) не тянем —
эвристика, но с реальными кейсами справляется.

Использовать везде, где нужно понять «это одна организация или
разные»: sni_host_mismatch, dns_answer_mismatch, sni_cert_mismatch,
typosquatting, allowlist-проверки.
"""
from __future__ import annotations

# v0.9.0: two-level TLD support

# Двухуровневые публичные суффиксы, которые встречаются в реальных pcap.
_TWO_LEVEL_SUFFIXES: frozenset[str] = frozenset({
    # United Kingdom
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "sch.uk", "ltd.uk", "plc.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    # Korea
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    # South Africa
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    # Israel
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    # India
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "firm.in",
    # Turkey
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "gen.tr", "web.tr",
    # Mexico
    "com.mx", "net.mx", "org.mx", "edu.mx", "gob.mx",
    # Argentina
    "com.ar", "net.ar", "org.ar", "edu.ar", "gob.ar",
    # Taiwan
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
    # Hong Kong
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    # Singapore
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
    # Malaysia
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    # Philippines
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    # Vietnam
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    # Thailand
    "co.th", "or.th", "ac.th", "go.th", "in.th", "net.th",
    # Indonesia
    "co.id", "or.id", "ac.id", "go.id", "web.id", "sch.id",
    # Ukraine
    "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua", "in.ua",
    # Poland
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl",
})


def _normalize(host: str) -> str:
    return (host or "").lower().rstrip(".")


def split_domain(host: str) -> tuple[str, str]:
    """
    Разделить домен на (base, rest).

    base — минимальный регистрируемый домен (SLD + публичный суффикс).
    rest — поддомены слева.

    Примеры:
      "a.b.foo.co.uk"   -> ("foo.co.uk", "a.b")
      "api.example.com" -> ("example.com", "api")
      "example.com"     -> ("example.com", "")
      "localhost"       -> ("localhost", "")
      ""                -> ("", "")
    """
    h = _normalize(host)
    if not h:
        return ("", "")
    parts = h.split(".")
    if len(parts) < 2:
        return (h, "")

    # Проверяем двухуровневый суффикс (только если есть что резать).
    if len(parts) >= 3:
        two = ".".join(parts[-2:])
        if two in _TWO_LEVEL_SUFFIXES:
            base = ".".join(parts[-3:])
            rest = ".".join(parts[:-3])
            return (base, rest)

    base = ".".join(parts[-2:])
    rest = ".".join(parts[:-2])
    return (base, rest)


def base_domain(host: str) -> str:
    """
    Минимальный регистрируемый домен.

    api.example.com -> example.com
    a.b.foo.co.uk   -> foo.co.uk
    attacker.com    -> attacker.com
    """
    return split_domain(host)[0]


def registered_label(host: str) -> str:
    """
    Метка регистрируемого домена (SLD без TLD).

    api.example.com     -> example
    a.b.foo.co.uk       -> foo
    googleads.g.doubleclick.net -> doubleclick
    """
    base = base_domain(host)
    if not base:
        return ""
    parts = base.split(".")
    return parts[0] if parts else ""


def matches_suffix(host: str, suffixes) -> bool:
    """
    endswith по доменному суффиксу с обязательной точкой.

    notgoogle-analytics.com НЕ matches google-analytics.com
    (нужна точка перед суффиксом или полное совпадение).

    Суффиксы могут быть и двухуровневыми (co.uk) — берём as-is,
    сравнение построено на точках.
    """
    if not host:
        return False
    v = _normalize(host)
    for s in suffixes:
        s = _normalize(s)
        if not s:
            continue
        if v == s or v.endswith("." + s):
            return True
    return False
