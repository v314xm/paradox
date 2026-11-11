"""TLS-факты: SNI vs Host, JA3/UA-мимикрия и X.509-сертификаты.

Вынесено из ``facts.py``; обслуживает правила sni_without_dns,
sni_host_mismatch, dns_answer_mismatch, ja3_ua_mismatch,
sni_cert_mismatch, self_signed_cert и expired_cert.
"""
from __future__ import annotations

from datetime import UTC
from ipaddress import ip_address

from paradox.config import Config
from paradox.contradictions.base import Fact
from paradox.models import CaptureState

# =====================================================================
# TLS host facts: SNI vs HTTP Host (для sni_host_mismatch)
# =====================================================================

def _suffix_match(value: str, suffixes: frozenset[str]) -> bool:
    """Обёртка над domain_utils.matches_suffix (v0.9.0)."""
    from paradox.domain_utils import matches_suffix
    return matches_suffix(value, suffixes)


def _base_domain(host: str) -> str:
    """
    v0.9.0: минимальный регистрируемый домен с поддержкой
    двухуровневых TLD (co.uk, com.au, co.jp, ...).

    api.example.com → example.com
    a.b.foo.co.uk   → foo.co.uk
    attacker.com    → attacker.com
    """
    from paradox.domain_utils import base_domain
    return base_domain(host)


def _collect_ips_for(
    name: str,
    dns_by_name: dict[str, set[str]],
    max_depth: int = 5,
) -> set[str]:
    """
    Собрать все IP, достижимые от name через CNAME-цепочку.

    Пример: name=www.foo.com,
      dns_by_name['www.foo.com'] = {'cdn.foo.com'},
      dns_by_name['cdn.foo.com'] = {'1.2.3.4'}
    → вернёт {'1.2.3.4'}

    Логика различения CNAME vs A-запись: если значение встречается
    как ключ в dns_by_name — это CNAME-таргет (домен), идём дальше.
    Иначе считаем IP. Ограничение max_depth защищает от циклов.
    """
    ips: set[str] = set()
    seen: set[str] = {name}
    queue: list[tuple[str, int]] = [(name, 0)]
    while queue:
        cur, depth = queue.pop(0)
        if depth > max_depth:
            continue
        for val in dns_by_name.get(cur, ()):
            if val in dns_by_name:
                if val not in seen:
                    seen.add(val)
                    queue.append((val, depth + 1))
            else:
                # Только реальные IP: CNAME-таргет без захваченного
                # ответа (cdn.foo.com) иначе попадал в «resolved IPs»
                # и давал ложный dns_answer_mismatch.
                try:
                    ip_address(val)
                except ValueError:
                    continue
                ips.add(val)
    return ips


def extract_tls_host_facts(
    state: CaptureState,
    config: Config,
) -> list[Fact]:
    """
    Факты sni / http_host из flows.

    Фильтрация allowlist — здесь, не в правиле. Это позволяет правилу
    остаться чистым компаратором (только SNI vs Host) и не знать про
    конфиг. CDN/DoH — норма для mismatch, отфильтровываем заранее.

    Один факт на flow × (sni|host). Если у flow есть и SNI, и Host —
    два факта с общим evidence (dst_ip/dst_port) — по ним правило
    сгруппирует.

    ОГРАНИЧЕНИЕ: в реальности SNI в TLS ClientHello (порт 443), а
    HTTP Host — только в plaintext HTTP (обычно 80). Оба одновременно
    на одном flow — редкость. Внутри TLS Host не видим (шифр).
    Поэтому правило ловит узкий кейс — TLS на нестандартном порту +
    HTTP на том же соединении. На FIN-2015 это даёт 0 срабатываний.
    Не баг — ограничение видимости.
    """
    allow_doh = config.sni_mismatch_allowlist
    allow_cdn = config.beaconing_allowlist_suffixes
    allow_brands = config.legitimate_brand_domains

    # Резолв-проверка: домен считается разрешённым, если он
    # упоминается в dns_answers_by_name либо как ключ (прямой A-запрос),
    # либо как значение (CNAME-таргет в цепочке другого запроса).
    # Так ловим случай: клиент резолвил www.foo.com, а SNI = cdn.foo.com
    # (CNAME-таргет того же запроса) — не FP.
    dns_all_values: set[str] = set()
    for ips in state.dns_answers_by_name.values():
        dns_all_values |= ips

    facts: list[Fact] = []
    for key, flow in state.flows.items():
        dst_info = {
            "dst_ip": key.dst_ip,
            "dst_port": key.dst_port,
            "src_port": key.src_port,
        }
        ts = flow.first_ts if flow.first_ts is not None else 0.0

        if flow.sni:
            sni = flow.sni.lower().rstrip(".")
            if not (_suffix_match(sni, allow_doh)
                    or _suffix_match(sni, allow_cdn)
                    or _suffix_match(sni, allow_brands)):
                resolved = (
                    sni in state.dns_answers_by_name
                    or sni in dns_all_values
                )
                # resolved_ips: все IP, достижимые от sni через
                # CNAME-цепочку. Нужно правилу h_dns_answer_mismatch:
                # «dst_ip входит в резолвленный набор или нет».
                resolved_ips = _collect_ips_for(
                    sni, state.dns_answers_by_name,
                ) if resolved else set()
                facts.append(Fact(
                    source="sni",
                    subject=key.src_ip,
                    predicate="sni",
                    value=sni,
                    ts=ts,
                    confidence=0.9,
                    evidence={
                        **dst_info,
                        "resolved": resolved,
                        "resolved_ips": sorted(resolved_ips),
                    },
                ))

        if flow.http_host:
            host = flow.http_host.lower().rstrip(".")
            if not (_suffix_match(host, allow_doh)
                    or _suffix_match(host, allow_cdn)):
                facts.append(Fact(
                    source="http_host",
                    subject=key.src_ip,
                    predicate="http_host",
                    value=host,
                    ts=ts,
                    confidence=0.9,
                    evidence=dict(dst_info),
                ))

    return facts


# =====================================================================
# JA3 / UA facts: мимикрия клиента (для ja3_ua_mismatch)
# =====================================================================

# Маркеры UA-строк. Порядок обхода: сначала tools — они специфичнее.
# Chrome UA редко содержит "curl/", но python-requests может
# маскироваться, вставив "Chrome/120" в UA — поэтому сначала tools.
_UA_BROWSER_MARKERS: dict[str, str] = {
    "chrome":  "chrome",
    "firefox": "firefox",
    "edg/":    "edge",     # Edge: "Mozilla/5.0 ... Edg/120"
    "safari":  "safari",
}
_UA_TOOL_MARKERS: dict[str, str] = {
    "python-requests": "python",
    "python-urllib":   "python",
    "python/":         "python",
    "curl/":           "curl",
    "wget/":           "wget",
    "go-http-client":  "go",
}


# JA3-семейства, которые «интересны» правилу ja3_ua_mismatch.
# Только malware и tools. Всё остальное — "normal", не сравниваем.
#
# Это осознанный отказ от угадывания Chrome/Firefox в лицо: их
# хешей у нас нет, а выдумывать — источник FP. Пусть Chrome-JA3
# остаётся "normal" и не порождает фактов.
_ACTIONABLE_JA3_FAMILIES: frozenset[str] = frozenset({
    "malware", "tool", "python", "go", "curl", "wget",
})


def _classify_ja3(ja3: str, config: Config) -> str:
    """
    Классификация JA3-хеша:

      "malware" — Cobalt Strike, Tor, Dridex, Trickbot, Emotet
      "python"  — python-requests, python-urllib
      "go"      — go-http-client
      "curl"    — curl (если добавишь хеш в config)
      "wget"    — wget
      "tool"    — известный инструмент, но не опознали конкретно
      "normal"  — не в списках. Считаем, что это браузер или
                  легитимный клиент. Правило ja3_ua_mismatch такие
                  игнорирует.

    Возвращает строку, не enum: так проще логировать и отлаживать.
    """
    if ja3 in config.ja3_known_malware:
        return "malware"
    if ja3 in config.ja3_known_tools:
        name = config.ja3_known_tools[ja3].lower()
        if "python" in name:
            return "python"
        if "go-http" in name or name.startswith("go"):
            return "go"
        if "curl" in name:
            return "curl"
        if "wget" in name:
            return "wget"
        # Браузерные JA3 из конфига: без этого они попадали в "tool",
        # и ветка «браузерный TLS + скриптовый UA» не срабатывала.
        for family in ("chrome", "firefox", "edge", "safari"):
            if family in name:
                return family
        return "tool"
    return "normal"


def _classify_ua(ua: str) -> str:
    """
    Короткое семейство UA-строки:

      chrome / firefox / edge / safari — браузеры
      python / curl / wget / go        — инструменты
      unknown                          — ничего не опознали
    """
    if not ua:
        return "unknown"
    u = ua.lower()
    # Сначала tools — они специфичнее
    for marker, family in _UA_TOOL_MARKERS.items():
        if marker in u:
            return family
    for marker, family in _UA_BROWSER_MARKERS.items():
        if marker in u:
            return family
    return "unknown"


def extract_ja3_ua_facts(
    state: CaptureState,
    config: Config,
) -> list[Fact]:
    """
    Факты uses_ja3 и uses_ua по клиенту (src_ip).

    Один факт на (src_ip, ja3) и один на (src_ip, ua). Правило
    ja3_ua_mismatch группирует по src_ip и ищет несовместимые
    пары — например, python-requests и Chrome-UA с одного хоста.

    Почему per-client, а не per-flow:

      JA3 в TLS ClientHello (внутри), UA в HTTP-запросе. Обычно
      это разные соединения (443 и 80). Даже если TLS на 443 —
      внутри HTTP-запроса мы не видим, шифр. Один и тот же flow
      с ja3 и http_user_agent — почти невозможен.

      Per-client ловит реальный сценарий: скрипт ходит на API
      (JA3 = python-requests) и параллельно мимикрирует под
      браузер для HTTP-запросов (UA = Chrome). Это мимикрия.

    Отбрасываем нормальные JA3 (`"normal"`) сразу — они не дают
    сравнения. Из UA оставляем всё, что опознали (браузеры и tools).
    """
    facts: list[Fact] = []

    for key, flow in state.flows.items():
        src = key.src_ip
        ts = flow.first_ts if flow.first_ts is not None else 0.0

        if flow.ja3:
            family = _classify_ja3(flow.ja3, config)
            # Оставляем только actionable: malware или tools.
            # "normal" (неопознанные, обычно браузеры) — не
            # интересны правилу, отбрасываем. Иначе получим тысячи
            # фактов без шанса на срабатывание.
            if family in _ACTIONABLE_JA3_FAMILIES:
                facts.append(Fact(
                    source="ja3",
                    subject=src,
                    predicate="uses_ja3",
                    value=flow.ja3,
                    ts=ts,
                    confidence=0.9,
                    evidence={
                        "family": family,
                        "dst_ip": key.dst_ip,
                        "dst_port": key.dst_port,
                    },
                ))

        if flow.http_user_agent:
            family = _classify_ua(flow.http_user_agent)
            if family != "unknown":
                facts.append(Fact(
                    source="http_ua",
                    subject=src,
                    predicate="uses_ua",
                    value=flow.http_user_agent,
                    ts=ts,
                    confidence=0.85,
                    evidence={
                        "family": family,
                        "dst_ip": key.dst_ip,
                        "dst_port": key.dst_port,
                    },
                ))

    return facts

# =====================================================================
# TLS certificate facts: для sni_cert_mismatch / self_signed / expired
# =====================================================================

def _parse_iso_ts(iso: str) -> float:
    """ISO-строка из X.509 (UTC) → unix timestamp. 0.0 на битом."""
    from datetime import datetime
    try:
        dt = datetime.fromisoformat(iso).replace(tzinfo=UTC)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


def extract_tls_cert_facts(state: CaptureState) -> list[Fact]:
    """
    Факты tls_cert: одна запись на каждый распарсенный сертификат.

    Источник — `state.tls_certs`, список (FlowKey, Certificate).
    Заполняется TlsCertificateExtractor после TCP-reassembly.

    В evidence кладём всё, что нужно трём правилам:
      - sni (из flow, если есть)
      - subject_cn, issuer_cn
      - is_self_signed
      - not_before_iso, not_after_iso, not_after_ts
      - san_dns, san_ips
      - dst_ip, dst_port, first_ts

    Один Fact = один сертификат. Группировку и анализ делают правила.
    """
    facts: list[Fact] = []
    for key, cert in state.tls_certs:
        flow = state.flows.get(key)
        if flow is None:
            continue
        sni = flow.sni or ""
        ts = flow.first_ts if flow.first_ts is not None else 0.0

        facts.append(Fact(
            source="tls_cert",
            subject=key.src_ip,
            predicate="tls_cert",
            value=cert.subject_cn or "",
            ts=ts,
            confidence=0.9,
            evidence={
                "sni": sni,
                "subject_cn": cert.subject_cn,
                "issuer_cn": cert.issuer_cn,
                "is_self_signed": cert.is_self_signed,
                "not_before": cert.not_before,
                "not_after": cert.not_after,
                "not_after_ts": (
                    _parse_iso_ts(cert.not_after)
                    if cert.not_after else 0.0
                ),
                "san_dns": list(cert.san_dns),
                "san_ips": list(cert.san_ips),
                "dst_ip": key.dst_ip,
                "dst_port": key.dst_port,
            },
        ))

    return facts
