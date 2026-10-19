"""
Markdown-рендер отчёта.

Берёт dict от run_pipeline, возвращает строку в Markdown.
Цель — то, что аналитик копирует в тикет или вики.

Принцип: то же самое, что в JSON, но человекочитаемо.
Не парсим JSON обратно — работаем с dict напрямую.

Структура отчёта (0.7.0):
1. Header (мета)
2. TL;DR — что произошло, кто атакует, что скачано (в порядке kill-chain)
3. Timeline — хронология findings
4. Carved Files — метаданные payload'ов
5. Сводка — числа
6. Сущности — внутренние, внешние (с ролью pivot)
7. Findings — с MITRE-маппингом
8. Противоречия — несогласованности между источниками
9. HTTP — хосты, URI, UA
10. IOC — домены, IP, порты
11. Топ-10 flows
"""
from __future__ import annotations

# v0.8.0: timeline

from ipaddress import ip_address


# ---------------------------------------------------------------------
# MITRE ATT&CK маппинг: тип finding → ID + тактика
# Источник: https://attack.mitre.org/
#
# ВАЖНО: это fallback. Если у Finding есть instance-level
# mitre_techniques (заполнены детектором — например large_transfer
# по direction), используем их, а не этот словарь.
# ---------------------------------------------------------------------
_MITRE_MAP: dict[str, str] = {
    "brute_force":        "T1110 (Brute Force)",
    "ftp_brute_force":    "T1110.001 (Password Guessing)",
    "command_injection":  "T1059 (Command & Scripting Interpreter)",
    "script_download":    "T1105 (Ingress Tool Transfer)",
    "lateral_movement":   "T1021 (Remote Services)",
    "large_transfer":     "T1041 (Exfil Over C2 Channel)",
    "beaconing":          "T1071 (Application Layer Protocol)",
    "dns_tunneling":      "T1071.004 (DNS)",
    "dga_domain":         "T1568.002 (Domain Generation Algorithms)",
    "typosquatting":      "T1583.001 (Acquire Infrastructure: Domains)",
    "vulnerable_path":    "T1190 (Exploit Public-Facing App)",
    "web_scanner":        "T1595.002 (Vulnerability Scanning)",
    "port_scan":          "T1046 (Network Service Discovery)",
    "sni_without_dns":    "T1071.001 (Web Protocols)",
    "ja3_malware":        "T1071.001 (Web Protocols)",
    "ja3_tool":           "—",
    "cloud_tunnel":       "T1572 (Protocol Tunneling)",
    "ip_check_service":   "T1590.005 (IP Addresses)",
    "nxdomain_burst":     "T1568 (Dynamic Resolution)",
    "suspicious_port":    "T1571 (Non-Standard Port)",
    "carved_file":        "T1105 (Ingress Tool Transfer)",
}


# ---------------------------------------------------------------------
# Kill-chain ordering
# Порядок отражает типичную последовательность атаки.
# Не найденные типы не влияют; незнакомые типы уезжают в конец.
# ---------------------------------------------------------------------
_CHAIN_ORDER: dict[str, int] = {
    "pivot":              5,   # pivot — уже компромисс, показываем первым
    "web_scanner":       10,
    "port_scan":         20,
    "vulnerable_path":   30,
    "command_injection": 40,
    "brute_force":       50,
    "ftp_brute_force":   55,
    "script_download":   60,
    "carved_file":       65,
    "suspicious_port":   70,
    "ja3_malware":       75,
    "ja3_tool":          76,
    "beaconing":         80,
    "dns_tunneling":     82,
    "dga_domain":        84,
    "nxdomain_burst":    86,
    "typosquatting":     88,
    "cloud_tunnel":      90,
    "sni_without_dns":   92,
    "ip_check_service":  94,
    "lateral_movement": 100,
    "large_transfer":   110,
}
_CHAIN_UNKNOWN = 999


# ---------------------------------------------------------------------
# Форматтеры
# ---------------------------------------------------------------------

def _fmt_bytes(n: int) -> str:
    """Человекочитаемый размер."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_duration(seconds: float) -> str:
    """Человекочитаемая длительность."""
    if seconds < 60:
        return f"{seconds:.1f} сек"
    if seconds < 3600:
        return f"{seconds / 60:.1f} мин"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} ч"
    return f"{seconds / 86400:.1f} дн"


def _fmt_rel(seconds: float) -> str:
    """Время в формате H:MM:SS для timeline."""
    if seconds < 0:
        seconds = 0
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


def _short(s: str, n: int = 40) -> str:
    """Обрезать длинную строку с многоточием."""
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _fmt_host(host: str | None) -> str:
    """
    Host из HTTP-таблицы. Если это IP-литерал — помечаем как unknown host.
    Иначе — обычное имя.
    """
    if not host:
        return "?"
    try:
        ip_address(host)
    except ValueError:
        return host
    return f"{host} (unknown host)"


# ---------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------

def _mitre_for_finding(f: dict) -> str:
    """
    Instance-level mitre_techniques приоритетнее type-map.

    large_transfer знает про T1041/T1105 сам (по direction),
    а _MITRE_MAP знает только общий T1041.
    """
    techniques = f.get("mitre_techniques") or ()
    if techniques:
        return ", ".join(techniques)
    return _MITRE_MAP.get(f.get("type", ""), "—")


# Совместимость: старое имя, использовалось в timeline/findings.
def _mitre_for(finding_type: str) -> str:
    return _MITRE_MAP.get(finding_type, "—")


# ---------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------

def _extract_iocs(findings: list[dict]) -> dict:
    """Простое извлечение IOC из findings."""
    domains: dict[str, list[str]] = {}
    ips: dict[str, list[str]] = {}
    ports: dict[int, list[str]] = {}

    for f in findings:
        ftype = f.get("type", "")
        value = f.get("value", "")

        if ftype in ("dga_domain", "cloud_tunnel_domain",
                     "ip_check_service", "typosquatting",
                     "sni_without_dns"):
            domains.setdefault(value, []).append(ftype)

        elif ftype == "suspicious_port":
            if ":" in value:
                ip, port_s = value.rsplit(":", 1)
                ips.setdefault(ip, []).append(ftype)
                try:
                    ports.setdefault(int(port_s), []).append(ftype)
                except ValueError:
                    pass

        elif ftype == "nxdomain_burst":
            ips.setdefault(value, []).append(ftype)

    return {"domains": domains, "ips": ips, "ports": ports}


# ---------------------------------------------------------------------
# TL;DR
# ---------------------------------------------------------------------

def _pick_first_with_role(entities: list[dict], role: str) -> str | None:
    for e in entities:
        if role in e.get("roles", []):
            return e.get("ip")
    return None


def _unique_finding_types(findings: list[dict]) -> list[str]:
    seen: list[str] = []
    for f in findings:
        t = f.get("type")
        if t and t not in seen:
            seen.append(t)
    return seen


def _chain_for(findings: list[dict]) -> list[str]:
    """
    Уникальные типы findings в порядке kill-chain.

    Приоритет — цепочка, а не confidence: аналитик должен видеть
    «скан → RCE → payload → beacon», даже если beacon confidence выше.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for f in findings:
        t = f.get("type")
        if t and t not in seen:
            seen.add(t)
            ordered.append(t)
    return sorted(
        ordered,
        key=lambda t: (_CHAIN_ORDER.get(t, _CHAIN_UNKNOWN), t),
    )


def _render_tldr(report: dict) -> list[str]:
    """Короткий TL;DR: что произошло, кто атакует, что скачано."""
    findings = report.get("findings", [])
    entities = report.get("entities", {})
    internal = entities.get("internal", [])
    carved = report.get("carved_files", {}).get("files", [])
    contradictions = report.get("contradictions") or []

    lines: list[str] = ["## TL;DR", ""]

    if not findings and not contradictions:
        lines.append("_Findings нет. Трафик выглядит чистым на уровне эвристик._")
        lines.append("")
        return lines

    attacker = _pick_first_with_role(internal, "attacker_candidate")
    victim = _pick_first_with_role(internal, "victim_candidate")
    pivot = _pick_first_with_role(internal, "pivot")

    # Основное предложение — цепочка в порядке kill-chain.
    types = _chain_for(findings)
    types_str = " → ".join(f"`{t}`" for t in types) if types else "—"

    if pivot:
        lines.append(
            f"**PIVOT:** `{pivot}` — скомпрометирован и атакует дальше. "
            f"Типы: {types_str}."
        )
    elif attacker and victim:
        lines.append(
            f"**Инцидент:** `{attacker}` атакует `{victim}`. "
            f"Типы: {types_str}."
        )
    elif victim:
        lines.append(f"**Жертва:** `{victim}`. Типы: {types_str}.")
    elif attacker:
        lines.append(f"**Атакующий:** `{attacker}`. Типы: {types_str}.")
    else:
        lines.append(f"**Findings:** {types_str}.")
    lines.append("")

    # Ключевое — список
    if pivot:
        lines.append(f"- **Pivot:** `{pivot}` (внутренний, критично)")
    if attacker:
        lines.append(f"- Attacker: `{attacker}` (internal)")
    if victim:
        lines.append(f"- Victim: `{victim}` (internal)")

    # Payloads
    for f in carved[:3]:
        uri = f.get("uri", "?")
        size = f.get("size", 0)
        sha = (f.get("sha256") or "")[:16]
        ext = f.get("ext") or "?"
        lines.append(
            f"- Payload: `{uri}` ({ext}, {size} B, sha256 `{sha}…`)"
        )
    if len(carved) > 3:
        lines.append(f"- _(ещё {len(carved) - 3} payload'ов — см. Carved Files)_")

    # High-confidence findings
    high = [f for f in findings if f.get("confidence", 0) >= 0.85]
    if high:
        lines.append("")
        lines.append(f"**High-confidence ({len(high)}):**")
        for f in high[:5]:
            ftype = f.get("type", "?")
            value = _short(f.get("value", "?"), 70)
            lines.append(f"- `{ftype}` — `{value}` ({f.get('confidence', 0):.2f})")

    # Contradictions, если есть — короткая ссылка на секцию.
    if contradictions:
        lines.append("")
        lines.append(
            f"**Противоречия:** {len(contradictions)} — см. секцию ниже."
        )

    lines.append("")
    return lines


# ---------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------

def _escape_cell(s: str) -> str:
    """Экранировать | для markdown-таблицы."""
    return (s or "").replace("|", "\\|")


def _render_timeline(report: dict, top_n: int = 50) -> list[str]:
    """
    Хронология findings + contradictions по фазам kill-chain.

    v0.8.0: читаем report["timeline"] — плоский список событий,
    отсортированный по ts. Группируем по phase (kill-chain), внутри
    фазы — таблица событий. Fallback на старое поведение, если
    timeline в отчёте отсутствует.
    """
    timeline = report.get("timeline")
    if not timeline:
        return _render_timeline_fallback(report, top_n=15)

    lines: list[str] = ["## Timeline", ""]
    lines.append(
        "_Хронология findings и противоречий по фазам kill-chain. "
        "Время — относительно первого события._"
    )
    lines.append("")

    # t0 — минимум ts среди всех событий.
    t0 = min(e.get("ts", 0.0) for e in timeline)

    # Группировка по phase, порядок фаз — по chain_order.
    by_phase: dict[str, list[dict]] = {}
    phase_order: dict[str, int] = {}
    for e in timeline:
        phase = e.get("phase", "other")
        by_phase.setdefault(phase, []).append(e)
        phase_order[phase] = e.get("chain_order", 999)

    ordered_phases = sorted(
        by_phase.keys(),
        key=lambda p: (phase_order.get(p, 999), p),
    )

    shown = 0
    for phase in ordered_phases:
        events = by_phase[phase]
        lines.append(f"### {phase} ({len(events)})")
        lines.append("")
        lines.append(
            "| Время (rel) | Kind | Тип | Subject | Описание | Conf | MITRE |"
        )
        lines.append("|---|---|---|---|---|---|---|")
        for e in events:
            if shown >= top_n:
                break
            rel = _fmt_rel(e.get("ts", 0.0) - t0)
            kind = e.get("kind", "?")
            etype = _escape_cell(e.get("type", "?"))
            subject = _escape_cell(_short(e.get("subject") or "?", 20))
            desc = _escape_cell(_short(e.get("description") or "", 70))
            conf = e.get("confidence", 0.0)
            mitre = e.get("mitre_id") or "—"
            lines.append(
                f"| {rel} | `{kind}` | `{etype}` | `{subject}` | "
                f"{desc} | {conf:.2f} | {mitre} |"
            )
            shown += 1
        lines.append("")
        if shown >= top_n:
            remaining = len(timeline) - shown
            if remaining > 0:
                lines.append(
                    f"_…и ещё {remaining} событий — см. JSON-отчёт._"
                )
                lines.append("")
            break

    return lines


def _render_timeline_fallback(report: dict, top_n: int = 15) -> list[str]:
    """
    Fallback для отчётов без report["timeline"] (до v0.8.0).

    Плоская хронология findings по first_seen — как было раньше.
    """
    findings = report.get("findings", [])
    lines: list[str] = ["## Timeline", ""]

    with_ts = [f for f in findings if f.get("first_seen") is not None]
    if not with_ts:
        lines.append("_Нет timestamps у findings._")
        lines.append("")
        return lines

    t0 = min(f["first_seen"] for f in with_ts)
    sorted_f = sorted(with_ts, key=lambda f: f["first_seen"])

    lines.append("| Время (rel) | Тип | Значение | Conf | MITRE |")
    lines.append("|---|---|---|---|---|")
    for f in sorted_f[:top_n]:
        rel = _fmt_rel(f["first_seen"] - t0)
        ftype = f.get("type", "?")
        value = _short(f.get("value", "?"), 60)
        conf = f.get("confidence", 0.0)
        mitre = _mitre_for_finding(f)
        lines.append(
            f"| {rel} | `{ftype}` | {value} | {conf:.2f} | {mitre} |"
        )
    if len(sorted_f) > top_n:
        lines.append(f"| ... | _(ещё {len(sorted_f) - top_n})_ | | | |")
    lines.append("")
    return lines


# ---------------------------------------------------------------------
# Carved files (опционально — если есть)
# ---------------------------------------------------------------------

def _render_carved_files(report: dict) -> list[str]:
    carved = report.get("carved_files", {}).get("files", [])
    if not carved:
        return []

    lines: list[str] = [f"## Carved Files ({len(carved)})", ""]
    lines.append("_Metadata-only. Тело на диск не пишется._")
    lines.append("")
    lines.append("| URI | Ext | Size | SHA256 | First bytes (hex) |")
    lines.append("|---|---|---|---|---|")
    for f in carved:
        uri = _short(f.get("uri", "?"), 50)
        ext = f.get("ext") or "?"
        size = f.get("size", 0)
        sha = (f.get("sha256") or "")[:16]
        fb = _short(f.get("first_bytes_hex", "") or "", 32)
        lines.append(
            f"| `{uri}` | `{ext}` | {size} B | `{sha}…` | `{fb}` |"
        )
    lines.append("")
    return lines


# ---------------------------------------------------------------------
# Contradictions
# ---------------------------------------------------------------------

_SEVERITY_ICON: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪",
}


def _render_contradictions(report: dict) -> list[str]:
    contradictions = report.get("contradictions") or []
    if not contradictions:
        return []

    lines: list[str] = [f"## Противоречия ({len(contradictions)})", ""]
    lines.append(
        "_Несогласованности между источниками. Не атаки, а сигналы "
        "«одно из двух неверно, разберись»._"
    )
    lines.append("")

    for c in contradictions:
        sev = c.get("severity", "info")
        icon = _SEVERITY_ICON.get(sev, "·")
        rule = c.get("rule", "?")
        subject = c.get("subject", "?")
        conf = c.get("confidence", 0.0)

        lines.append(f"### {icon} `{rule}` — `{subject}` ({conf:.2f})")
        lines.append("")

        hint = c.get("resolution_hint")
        if hint:
            lines.append(f"> {hint}")
            lines.append("")

        lines.append("**Факты:**")
        lines.append("")
        for f in c.get("facts", []):
            src = f.get("source", "?")
            pred = f.get("predicate", "?")
            val = f.get("value") or "(unknown)"
            ts = f.get("ts", 0.0)
            fc = f.get("confidence", 0.0)
            # finding_type из evidence — отличает nxdomain_burst от port_scan
            # в отчёте, когда value пуст.
            ftype = (f.get("evidence") or {}).get("finding_type") or ""
            ftype_str = f" [{ftype}]" if ftype else ""
            lines.append(
                f"- `{pred}` ← `{val}`{ftype_str} "
                f"(source=`{src}`, ts={ts:.1f}, conf={fc:.2f})"
            )
        lines.append("")

        causes = c.get("likely_causes") or []
        if causes:
            lines.append("**Вероятные причины:**")
            lines.append("")
            for cause in causes:
                lines.append(f"- {cause}")
            lines.append("")

    return lines


# ---------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------

def render_markdown(report: dict) -> str:
    """Собрать Markdown-отчёт из dict run_pipeline."""
    lines: list[str] = []

    provenance = report.get("provenance", {})
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    flows = report.get("flows", {})
    entities = report.get("entities", {})
    http = report.get("http", {})
    top_flows = flows.get("top_by_bytes", [])
    contradictions = report.get("contradictions") or []

    # --- header ---
    pcap_path = provenance.get("pcap_path", "?")
    pcap_name = pcap_path.split("\\")[-1].split("/")[-1]
    lines.append(f"# PCAP Triage Report: `{pcap_name}`")
    lines.append("")

    lines.append(f"**Инструмент:** pcap-triage v{provenance.get('tool_version', '?')}  ")
    lines.append(f"**Файл:** `{pcap_path}`  ")
    lines.append(f"**SHA256:** `{provenance.get('pcap_sha256', '?')}`  ")
    lines.append("")

    # --- TL;DR ---
    lines.extend(_render_tldr(report))

    # --- Absence ---
    lines.extend(_render_absence(report))

    # --- Timeline ---
    if findings:
        lines.extend(_render_timeline(report))

    # --- Carved files ---
    carved_section = _render_carved_files(report)
    if carved_section:
        lines.extend(carved_section)

    # --- summary ---
    lines.append("## Сводка")
    lines.append("")
    lines.append(f"- **Пакеты:** {summary.get('packets', 0):,}")
    lines.append(f"- **Flows:** {summary.get('flows', 0):,}")
    lines.append(f"- **Уникальных DNS-запросов:** {summary.get('unique_dns_queries', 0)}")
    lines.append(f"- **NXDOMAIN:** {summary.get('nxdomain_count', 0)}")
    lines.append(f"- **Findings:** {summary.get('findings', 0)}")
    if contradictions:
        lines.append(f"- **Противоречий:** {len(contradictions)}")

    first_ts = summary.get("first_ts")
    last_ts = summary.get("last_ts")
    if first_ts and last_ts:
        duration = last_ts - first_ts
        lines.append(f"- **Период:** {_fmt_duration(duration)}")

    uploaded = summary.get("uploaded_bytes")
    downloaded = summary.get("downloaded_bytes")
    if uploaded is not None and downloaded is not None:
        lines.append(f"- **Uploaded (internal → external):** {_fmt_bytes(uploaded)}")
        lines.append(f"- **Downloaded (external → internal):** {_fmt_bytes(downloaded)}")

    extractor_errors = summary.get("extractor_errors") or {}
    if extractor_errors:
        lines.append(f"- **Ошибки экстракторов:** `{extractor_errors}`")
    lines.append("")

    # --- entities ---
    if entities:
        lines.extend(_render_entities(entities, findings))
        lines.append("")

    # --- NDP ---
    lines.extend(_render_ndp(report))

    # --- findings ---
    lines.extend(_render_findings(findings))

    # --- contradictions ---
    contradictions_section = _render_contradictions(report)
    if contradictions_section:
        lines.extend(contradictions_section)
        lines.append("")

    # --- HTTP ---
    if http:
        lines.extend(_render_http(http))
        lines.append("")

    # --- IOC ---
    iocs = _extract_iocs(findings)
    if iocs["domains"] or iocs["ips"] or iocs["ports"]:
        lines.append("## IOC")
        lines.append("")

        if iocs["domains"]:
            lines.append("**Домены:**")
            lines.append("")
            for domain, reasons in sorted(iocs["domains"].items()):
                lines.append(f"- `{domain}` — {', '.join(reasons)}")
            lines.append("")

        if iocs["ips"]:
            lines.append("**IP:**")
            lines.append("")
            for ip, reasons in sorted(iocs["ips"].items()):
                lines.append(f"- `{ip}` — {', '.join(reasons)}")
            lines.append("")

        if iocs["ports"]:
            lines.append("**Порты:**")
            lines.append("")
            for port, reasons in sorted(iocs["ports"].items()):
                lines.append(f"- `{port}` — {', '.join(reasons)}")
            lines.append("")

    # --- top flows ---
    if top_flows:
        lines.append("## Топ-10 flows по байтам")
        lines.append("")
        lines.append("| Src | Dst | Dir | Proto | Bytes | SNI |")
        lines.append("|---|---|---|---|---|---|")
        for fl in top_flows[:10]:
            src = f"{fl.get('src_ip', '?')}:{fl.get('src_port') or '-'}"
            dst = f"{fl.get('dst_ip', '?')}:{fl.get('dst_port') or '-'}"
            direction = fl.get("direction") or "—"
            proto = fl.get("proto", "?")
            b = _fmt_bytes(fl.get("bytes", 0))
            sni = _short(fl.get("sni") or "—", 60)
            lines.append(
                f"| `{src}` | `{dst}` | {direction} | {proto} | {b} | `{sni}` |"
            )
        lines.append("")

    # --- footer ---
    lines.append("---")
    lines.append("")
    lines.append("_Отчёт сгенерирован автоматически. Проверяй findings глазами: "
                 "эвристики дают кандидатов, не приговоры._")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------

def _render_findings(findings: list[dict]) -> list[str]:
    lines: list[str] = []
    if not findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("_Ничего не найдено._")
        lines.append("")
        return lines

def _finding_types_for(entity: dict, findings: list[dict]) -> list[str]:
    """Преобразовать findings_indices → список типов."""
    idxs = entity.get("findings_indices", []) or []
    types: list[str] = []
    for i in idxs:
        if 0 <= i < len(findings):
            t = findings[i].get("type")
            if t and t not in types:
                types.append(t)
    return types


def _render_entities(entities: dict, findings: list[dict]) -> list[str]:
    """Секция 'Сущности' в Markdown."""
    lines: list[str] = []

    internal = entities.get("internal", [])
    external = entities.get("external", [])

    if not internal and not external:
        return []

    lines.append("## Сущности")
    lines.append("")

    if internal:
        lines.append(f"### Внутренние хосты ({len(internal)})")
        lines.append("")
        for e in internal:
            ip = e.get("ip", "?")
            roles = e.get("roles", [])
            roles_str = ", ".join(f"`{r}`" for r in roles) if roles else "—"
            lines.append(f"**`{ip}`** — {roles_str}  ")

            fo = e.get("flows_out", 0)
            fi = e.get("flows_in", 0)
            bo = _fmt_bytes(e.get("bytes_out", 0))
            bi = _fmt_bytes(e.get("bytes_in", 0))
            lines.append(f"  {fo} flows out · {fi} in · ↓ {bi} · ↑ {bo}  ")

            mac = e.get("mac")
            hostname = e.get("hostname")
            username = e.get("username")
            realm = e.get("realm")
            if mac or hostname or username or realm:
                parts = []
                if hostname:
                    parts.append(f"hostname: `{hostname}`")
                if mac:
                    parts.append(f"MAC: `{mac}`")
                if username:
                    parts.append(f"username: `{username}`")
                if realm:
                    parts.append(f"realm: `{realm}`")
                lines.append("  " + " · ".join(parts) + "  ")

            sni = e.get("sni_domains", [])
            if sni:
                shown = ", ".join(f"`{d}`" for d in sni[:5])
                more = f" _(+{len(sni) - 5})_" if len(sni) > 5 else ""
                lines.append(f"  SNI: {shown}{more}  ")

            dns = e.get("dns_names", [])
            if dns:
                shown = ", ".join(f"`{d}`" for d in dns[:10])
                more = f" _(+{len(dns) - 10})_" if len(dns) > 10 else ""
                lines.append(f"  DNS: {shown}{more}  ")

            fnd_types = _finding_types_for(e, findings)
            if fnd_types:
                shown = ", ".join(f"`{t}`" for t in fnd_types)
                lines.append(f"  Findings: {shown}  ")

            lines.append("")

    external_with_findings = [e for e in external if e.get("findings_indices")]
    if external_with_findings:
        lines.append(f"### Внешние IP с findings ({len(external_with_findings)})")
        lines.append("")
        for e in external_with_findings:
            ip = e.get("ip", "?")
            roles = e.get("roles", [])
            roles_str = ", ".join(f"`{r}`" for r in roles) if roles else "—"
            lines.append(f"**`{ip}`** — {roles_str}  ")

            fi = e.get("flows_in", 0)
            fo = e.get("flows_out", 0)
            bi = _fmt_bytes(e.get("bytes_in", 0))
            bo = _fmt_bytes(e.get("bytes_out", 0))
            lines.append(f"  {fi} flows in · {fo} out · ↓ {bi} · ↑ {bo}  ")

            mac = e.get("mac")
            hostname = e.get("hostname")
            if mac or hostname:
                parts = []
                if hostname:
                    parts.append(f"hostname: `{hostname}`")
                if mac:
                    parts.append(f"MAC: `{mac}`")
                lines.append("  " + " · ".join(parts) + "  ")

            sni = e.get("sni_domains", [])
            if sni:
                shown = ", ".join(f"`{d}`" for d in sni[:5])
                lines.append(f"  SNI: {shown}  ")

            fnd_types = _finding_types_for(e, findings)
            if fnd_types:
                shown = ", ".join(f"`{t}`" for t in fnd_types)
                lines.append(f"  Findings: {shown}  ")

            lines.append("")

    external_clean = [e for e in external if not e.get("findings_indices")]
    if external_clean:
        lines.append("### Внешние IP без findings — топ-5")
        lines.append("")
        for e in external_clean[:5]:
            ip = e.get("ip", "?")
            fi = e.get("flows_in", 0)
            bi = _fmt_bytes(e.get("bytes_in", 0))
            lines.append(f"- `{ip}` — {fi} flows in, {bi}")
        lines.append("")

    return lines


# ---------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------

def _render_http(http: dict) -> list[str]:
    """Секция 'HTTP' в Markdown."""
    lines: list[str] = []

    unique_hosts = http.get("unique_hosts", 0)
    unique_uris = http.get("unique_uris", 0)
    unique_ua = http.get("unique_user_agents", 0)

    if not unique_hosts and not unique_uris:
        return []

    lines.append("## HTTP")
    lines.append("")

    methods = http.get("methods", []) or []
    if methods:
        method_str = ", ".join(
            f"{m.get('method', '?')}×{m.get('count', 0)}" for m in methods
        )
        lines.append(f"**Methods:** {method_str}  ")
    lines.append(f"**Hosts:** {unique_hosts} · **URIs:** {unique_uris} · "
                 f"**User-Agents:** {unique_ua}  ")
    lines.append("")

    top_hosts = http.get("top_hosts", []) or []
    if top_hosts:
        lines.append("### Топ Hosts")
        lines.append("")
        lines.append("| Count | Host |")
        lines.append("|---|---|")
        for h in top_hosts[:10]:
            host = _fmt_host(h.get("host"))
            lines.append(f"| {h.get('count', 0)} | `{host}` |")
        lines.append("")

    top_uris = http.get("top_uris", []) or []
    if top_uris:
        lines.append("### Топ URIs")
        lines.append("")
        lines.append("| Method | Host | URI | Src → Dst | UA | Bytes |")
        lines.append("|---|---|---|---|---|---|")
        for u in top_uris[:15]:
            method = u.get("method") or "?"
            host = _fmt_host(_short(u.get("host") or "?", 30))
            uri = _short(u.get("uri") or "?", 60)
            src = f"{u.get('src_ip', '?')}:?"
            dst = f"{u.get('dst_ip', '?')}:{u.get('dst_port') or '-'}"
            ua = _short(u.get("user_agent") or "", 40)
            b = _fmt_bytes(u.get("bytes", 0))
            lines.append(
                f"| `{method}` | `{host}` | `{uri}` | `{src}` → `{dst}` | {ua} | {b} |"
            )
        lines.append("")

    top_ua = http.get("top_user_agents", []) or []
    if top_ua:
        lines.append("### Топ User-Agents")
        lines.append("")
        for ua in top_ua[:10]:
            count = ua.get("count", 0)
            agent = _short(ua.get("user_agent") or "?", 80)
            lines.append(f"- ×{count} — `{agent}`")
        lines.append("")

    return lines

# ---------------------------------------------------------------------
# Новые секции (NDP и Absence)
# ---------------------------------------------------------------------

def _render_absence(report: dict) -> list[str]:
    absence = report.get("absence", {})
    dns = absence.get("dns_unanswered", [])
    tcp = absence.get("tcp_unanswered", [])

    if not dns and not tcp:
        return []

    lines = ["## Аномалии / Оборванные сессии", ""]

    if dns:
        lines.append("### DNS без ответа")
        lines.append("| Домен (QNAME) | Запросов |")
        lines.append("|---|---|")
        for d in dns:
            lines.append(f"| `{d.get('qname', '?')}` | {d.get('count', 0)} |")
        lines.append("")

    if tcp:
        lines.append("### TCP без ответа (SYN)")
        lines.append("| Src IP | Dst IP | Порт | Пакеты |")
        lines.append("|---|---|---|---|")
        for t in tcp:
            lines.append(f"| `{t.get('src_ip', '?')}` | `{t.get('dst_ip', '?')}` | {t.get('dst_port', '?')} | {t.get('packets', 0)} |")
        lines.append("")

    return lines

def _render_ndp(report: dict) -> list[str]:
    ndp = report.get("ndp", {})
    total = ndp.get("total", 0)
    neighbors = ndp.get("neighbors", [])
    routers = ndp.get("routers", [])

    if total == 0:
        return []

    lines = [f"## IPv6 / NDP ({total} пакетов)", ""]

    if routers:
        lines.append("### Роутеры (RA)")
        for r in routers:
            lines.append(f"- `{r}`")
        lines.append("")

    if neighbors:
        lines.append("### Соседи (NDP)")
        lines.append("| IPv6 | MAC |")
        lines.append("|---|---|")
        for n in neighbors:
            lines.append(f"| `{n.get('ip', '?')}` | `{n.get('mac', '?')}` |")
        lines.append("")

    return lines

