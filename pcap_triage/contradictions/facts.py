"""
Извлечение фактов из CaptureState + Findings.

Факты — атомарные утверждения (source, subject, predicate, value).
Правила contradictions работают с фактами, не с findings напрямую:
так проще тестировать и комбинировать источники (finding + flow +
+ dns + arp).

Ключевые идеи:

1. `value` — необязателен. Если находка говорит «X атакует кого-то»
   (port_scan по десяткам хостов) или «X резолвит DGA»
   (nxdomain_burst — множество несозданных доменов), конкретный
   контр-субъект неизвестен. Роль — известна. Правило
   victim_makes_attack проверяет subject, а не value: pivot остаётся
   pivot'ом и без точного адресата.

2. Полярность findings (кто атакует, кто жертва) синхронизирована
   с entities.py (блок role_tags). Если меняешь там — меняй здесь.

3. Разные источники — разные функции `extract_*`. Правила вызывают
   ту, которая им нужна, а не общий `extract_facts`. Это даёт
   независимое тестирование и избегает лишней работы: правилу
   mac_ip_conflict не нужны attack-факты.
"""
from __future__ import annotations

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding, make_session_key
from pcap_triage.net_utils import is_internal_ip
from pcap_triage.contradictions.base import Fact


# =====================================================================
# Attack facts: кто кого атакует по findings
# =====================================================================

# Типы findings, где src АТАКУЕТ dst.
# Полярность: src = attacker, dst = victim.
#
# Синхронизировано с entities.py (блок role_tags). Если добавляешь
# новый детектор атаки — обнови оба места.
_ATTACK_TYPES: frozenset[str] = frozenset({
    "brute_force",
    "ftp_brute_force",
    "vulnerable_path",
    "command_injection",
    "port_scan",
    "web_scanner",
    "lateral_movement",
})

# Типы findings, где src — ЖЕРТВА (или инициатор), dst — C2/exfil-получатель.
#
# suspicious_port: internal src стучится на C2 dst — src жертва, не
# атакующий. В entities.py та же полярность (victim_tag на src).
_VICTIM_SIGNAL_TYPES: frozenset[str] = frozenset({
    "beaconing",
    "dns_tunneling",
    "script_download",
    "nxdomain_burst",
    "ja3_malware",
    "sni_without_dns",
    "dga_domain",
    "cloud_tunnel",
    "ip_check_service",
    "typosquatting",
    "suspicious_port",
})


def _ts(f: Finding) -> float:
    """Timestamp для факта. 0.0 — если у finding нет first_seen."""
    return f.first_seen if f.first_seen is not None else 0.0


def extract_attack_facts(findings: list[Finding]) -> list[Fact]:
    """
    Факты victim_of / attacker_of из findings.

    Полярность:
      _ATTACK_TYPES        src→dst: attacker_of(src, dst) + victim_of(dst, src)
      _VICTIM_SIGNAL_TYPES src→dst: victim_of(src, dst) + attacker_of(dst, src)
      large_transfer        — по evidence.direction

    Отсутствующая сторона → value="". Например, port_scan не привязан
    к одной цели (их десятки), nxdomain_burst — не к одному домену.
    В этих случаях фиксируем роль, но без контр-субъекта: правило
    victim_makes_attack проверяет subject, ему value не нужен.
    """
    facts: list[Fact] = []

    for f in findings:
        ev = f.evidence or {}
        src = ev.get("src_ip")
        dst = ev.get("dst_ip")

        if f.type in _ATTACK_TYPES:
            if src:
                facts.append(Fact(
                    source="finding", subject=src,
                    predicate="attacker_of", value=dst or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "attacker"},
                ))
            if dst:
                facts.append(Fact(
                    source="finding", subject=dst,
                    predicate="victim_of", value=src,
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "victim"},
                ))

        elif f.type in _VICTIM_SIGNAL_TYPES:
            if src:
                facts.append(Fact(
                    source="finding", subject=src,
                    predicate="victim_of", value=dst or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "victim"},
                ))
            if dst:
                facts.append(Fact(
                    source="finding", subject=dst,
                    predicate="attacker_of", value=src,
                    ts=_ts(f), confidence=f.confidence,
                    evidence={"finding_type": f.type, "role": "c2"},
                ))

        elif f.type == "large_transfer":
            # direction — источник правды, вычислен в LargeTransferDetector.
            # outbound (internal → external): src жертва, утекает.
            # inbound  (external → internal): dst жертва, скачивает payload.
            # internal ↔ internal: не C2-канал, факт не генерим.
            direction = ev.get("direction")
            if direction == "outbound" and src:
                facts.append(Fact(
                    source="finding", subject=src,
                    predicate="victim_of", value=dst or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={
                        "finding_type": f.type, "role": "victim_exfil",
                    },
                ))
            elif direction == "inbound" and dst:
                facts.append(Fact(
                    source="finding", subject=dst,
                    predicate="victim_of", value=src or "",
                    ts=_ts(f), confidence=f.confidence,
                    evidence={
                        "finding_type": f.type, "role": "victim_ingress",
                    },
                ))

    return facts


# =====================================================================
# ARP facts: история MAC на IP (для mac_ip_conflict)
# =====================================================================

def _mac_confidence(count: int) -> float:
    """
    Уверенность в факте «этот MAC реально принадлежит этому IP».

    Эвристика по числу ARP-пакетов от этого MAC на этом IP:
      1 пакет   — 0.5  (gratuitous ARP, спуф-выброс, случайный)
      2 пакета  — 0.6
      3–4       — 0.75
      ≥5        — 0.9  (устойчивое присутствие, реальный хост)

    Порог 5 — из практики: реальный хост за сессию отправляет десятки
    ARP, спуфер может выдать 1-2 поддельных до обнаружения.
    """
    if count >= 5:
        return 0.9
    if count >= 3:
        return 0.75
    if count >= 2:
        return 0.6
    return 0.5


def extract_arp_facts(state: CaptureState) -> list[Fact]:
    """
    Факты has_mac из ARP-истории: один Fact на уникальный (IP, MAC).

    Источник — `state.arp_macs`, который заполняет ARPMacHistoryExtractor.
    Отдельный от `host_identities` (там только последний MAC, для
    отчёта сущностей).

    Правило mac_ip_conflict группирует по subject (IP) и ищет
    несколько MAC. Одиночный MAC → правило молчит.

    evidence несёт first_ts / last_ts / count — по ним правило
    определяет пересечение окон (spoof vs lease change).
    """
    facts: list[Fact] = []
    for ip, macs in state.arp_macs.items():
        for mac, entry in macs.items():
            first_ts, last_ts, count = entry[0], entry[1], entry[2]
            facts.append(Fact(
                source="arp",
                subject=ip,
                predicate="has_mac",
                value=mac,
                ts=first_ts,
                confidence=_mac_confidence(count),
                evidence={
                    "first_ts": first_ts,
                    "last_ts": last_ts,
                    "count": count,
                },
            ))
    return facts


# =====================================================================
# TLS host facts: SNI vs HTTP Host (для sni_host_mismatch)
# =====================================================================

def _suffix_match(value: str, suffixes: frozenset[str]) -> bool:
    """
    endswith по доменному суффиксу с обязательной точкой.

    www.google-analytics.com matches google-analytics.com
    notgoogle-analytics.com — НЕ matches (нужна точка перед суффиксом).
    """
    if not value:
        return False
    v = value.lower().rstrip(".")
    return any(v == s or v.endswith("." + s) for s in suffixes)


def _base_domain(host: str) -> str:
    """
    Грубое SLD: последние две метки. Не поддерживает co.uk, com.au —
    та же ограниченность, что и в typosquatting. Для проверки «это
    одна организация или разные» этого хватает.

    api.example.com → example.com
    cdn.legit.com   → legit.com
    attacker.com    → attacker.com
    """
    parts = host.rstrip(".").lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


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
                    or _suffix_match(sni, allow_cdn)):
                facts.append(Fact(
                    source="sni",
                    subject=key.src_ip,
                    predicate="sni",
                    value=sni,
                    ts=ts,
                    confidence=0.9,
                    evidence=dict(dst_info),
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
# Reverse asymmetry facts: пропорция трафика в сессии
# =====================================================================

def extract_asymmetry_facts(
    state: CaptureState,
    config: Config,
) -> list[Fact]:
    """
    Факты session_asymmetry: одна запись на internal ↔ external сессию.

    Группируем оба направления одного соединения (по make_session_key),
    суммируем байты относительно internal-стороны, считаем ratio.

    Что фильтруем:
      - сессии, где нет обеих сторон (только A→B без ответа);
      - internal ↔ internal и external ↔ external (там asymmetry
        не имеет смысла — нет «наружу»);
      - total_bytes < reverse_asymmetry_min_total_bytes.

    Что кладём в evidence:
      bytes_out / bytes_in — от internal-перспективы;
      ratio — max/min, при bytes_in == 0 → float("inf");
      external_ip, порты, proto — для hint'а в отчёте.

    Правило reverse_asymmetry решает severity по ratio — здесь
    только фильтр по абсолютному объёму.
    """
    # Ключ сессии → {ip: {"bytes": N, "port": P, "first": T, "last": T}}
    sessions: dict[tuple, dict[str, dict]] = {}

    for key, flow in state.flows.items():
        sk = make_session_key(key)
        bucket = sessions.setdefault(
            (sk.ip_lo, sk.port_lo, sk.ip_hi, sk.port_hi, sk.proto),
            {},
        )
        entry = bucket.setdefault(key.src_ip, {
            "bytes": 0, "port": key.src_port,
            "first": None, "last": None,
        })
        entry["bytes"] += flow.bytes_sent
        if flow.first_ts is not None:
            if entry["first"] is None or flow.first_ts < entry["first"]:
                entry["first"] = flow.first_ts
            if entry["last"] is None or flow.last_ts > entry["last"]:
                entry["last"] = flow.last_ts

    facts: list[Fact] = []
    min_total = config.reverse_asymmetry_min_total_bytes

    for session_key, sides in sessions.items():
        # Односторонняя сессия: только один src_ip. Пропускаем —
        # сравнивать не с чем, а ratio=∞ породит FP.
        if len(sides) < 2:
            continue

        ips = list(sides.keys())
        a_ip, b_ip = ips[0], ips[1]
        a, b = sides[a_ip], sides[b_ip]

        a_internal = is_internal_ip(a_ip, config)
        b_internal = is_internal_ip(b_ip, config)

        # Ровно одна сторона внутренняя — иначе пропускаем.
        if a_internal and not b_internal:
            internal_ip, external_ip = a_ip, b_ip
            bytes_out, bytes_in = a["bytes"], b["bytes"]
            internal_port, external_port = a["port"], b["port"]
            internal_side, external_side = a, b
        elif b_internal and not a_internal:
            internal_ip, external_ip = b_ip, a_ip
            bytes_out, bytes_in = b["bytes"], a["bytes"]
            internal_port, external_port = b["port"], a["port"]
            internal_side, external_side = b, a
        else:
            continue

        total = bytes_out + bytes_in
        if total < min_total:
            continue

        # ratio = большая / меньшая. bytes_in == 0 → бесконечность
        # (односторонний исходящий канал).
        if bytes_in == 0:
            ratio = float("inf") if bytes_out > 0 else 1.0
        elif bytes_out == 0:
            ratio = float("inf")
        else:
            ratio = max(bytes_out, bytes_in) / min(bytes_out, bytes_in)

        # Timestamp начала сессии — из обеих сторон, берём min.
        firsts = [
            s["first"] for s in (internal_side, external_side)
            if s["first"] is not None
        ]
        ts_first = min(firsts) if firsts else 0.0

        facts.append(Fact(
            source="flow",
            subject=internal_ip,
            predicate="session_asymmetry",
            value=f"{bytes_out}/{bytes_in}",
            ts=ts_first,
            confidence=1.0,
            evidence={
                "external_ip": external_ip,
                "internal_port": internal_port,
                "external_port": external_port,
                "proto": session_key[4],
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "total_bytes": total,
                "ratio": ratio,
            },
        ))

    return facts


# =====================================================================
# Общая точка входа
# =====================================================================

def extract_facts(
    state: CaptureState,
    findings: list[Finding],
    config: Config,
) -> list[Fact]:
    """
    Все факты из state + findings.

    ВНИМАНИЕ: эта функция используется только если кому-то нужны
    все факты сразу. Правила contradictions вызывают свои частные
    extract_* (extract_attack_facts, extract_arp_facts, ...),
    чтобы не делать лишнюю работу. Например, mac_ip_conflict не
    нужны attack-факты.

    Держим эту функцию для дебага и внешних вызовов.
    """
    return (
        extract_attack_facts(findings)
        + extract_arp_facts(state)
        + extract_tls_host_facts(state, config)
        + extract_ja3_ua_facts(state, config)
    )