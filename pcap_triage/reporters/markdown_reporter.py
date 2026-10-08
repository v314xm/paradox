"""
Markdown-рендер отчёта.

Берёт dict от run_pipeline, возвращает строку в Markdown.
Цель — то, что аналитик копирует в тикет или вики.

Принцип: то же самое, что в JSON, но человекочитаемо.
Не парсим JSON обратно — работаем с dict напрямую.
"""
from __future__ import annotations


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


def _short(s: str, n: int = 40) -> str:
    """Обрезать длинную строку с многоточием."""
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


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

    # --- header ---
    pcap_path = provenance.get("pcap_path", "?")
    pcap_name = pcap_path.split("\\")[-1].split("/")[-1]
    lines.append(f"# PCAP Triage Report: `{pcap_name}`")
    lines.append("")

    lines.append(f"**Инструмент:** pcap-triage v{provenance.get('tool_version', '?')}  ")
    lines.append(f"**Файл:** `{pcap_path}`  ")
    lines.append(f"**SHA256:** `{provenance.get('pcap_sha256', '?')}`  ")
    lines.append("")

    # --- summary ---
    lines.append("## Сводка")
    lines.append("")
    lines.append(f"- **Пакеты:** {summary.get('packets', 0):,}")
    lines.append(f"- **Flows:** {summary.get('flows', 0):,}")
    lines.append(f"- **Уникальных DNS-запросов:** {summary.get('unique_dns_queries', 0)}")
    lines.append(f"- **NXDOMAIN:** {summary.get('nxdomain_count', 0)}")
    lines.append(f"- **Findings:** {summary.get('findings', 0)}")

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
        lines.extend(_render_entities(entities))
        lines.append("")

    # --- findings ---
    if findings:
        lines.append(f"## Findings ({len(findings)})")
        lines.append("")
        lines.append("| # | Тип | Значение | Уверенность |")
        lines.append("|---|---|---|---|")
        for i, f in enumerate(findings):
            ftype = f.get("type", "?")
            value = f.get("value", "?")
            conf = f.get("confidence", 0.0)
            lines.append(f"| {i} | `{ftype}` | `{value}` | {conf:.2f} |")
        lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("_Ничего не найдено._")
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
            sni = fl.get("sni") or "—"
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


def _render_entities(entities: dict) -> list[str]:
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
            roles_str = ", ".join(roles)
            lines.append(f"**`{ip}`** — {roles_str}  ")

            fo = e.get("flows_out", 0)
            fi = e.get("flows_in", 0)
            bo = _fmt_bytes(e.get("bytes_out", 0))
            bi = _fmt_bytes(e.get("bytes_in", 0))
            lines.append(f"  {fo} flows out · {fi} in · ↓ {bi} · ↑ {bo}  ")

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
                more = f" _(+{len(sni) - 5})_" if len(sni) > 5 else ""
                lines.append(f"  SNI: {shown}{more}  ")

            dns = e.get("dns_names", [])
            if dns:
                shown = ", ".join(f"`{d}`" for d in dns[:10])
                more = f" _(+{len(dns) - 10})_" if len(dns) > 10 else ""
                lines.append(f"  DNS: {shown}{more}  ")

            fnd = e.get("findings_indices", [])
            if fnd:
                lines.append(f"  Findings: #{', #'.join(str(x) for x in fnd)}  ")

            lines.append("")

    external_with_findings = [e for e in external if e.get("findings_indices")]
    if external_with_findings:
        lines.append(f"### Внешние IP с findings ({len(external_with_findings)})")
        lines.append("")
        for e in external_with_findings:
            ip = e.get("ip", "?")
            roles = e.get("roles", [])
            roles_str = ", ".join(roles)
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

            fnd = e.get("findings_indices", [])
            lines.append(f"  Findings: #{', #'.join(str(x) for x in fnd)}  ")

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

    # methods
    methods = http.get("methods", []) or []
    if methods:
        method_str = ", ".join(
            f"{m.get('method', '?')}×{m.get('count', 0)}" for m in methods
        )
        lines.append(f"**Methods:** {method_str}  ")
    lines.append(f"**Hosts:** {unique_hosts} · **URIs:** {unique_uris} · "
                 f"**User-Agents:** {unique_ua}  ")
    lines.append("")

    # top hosts
    top_hosts = http.get("top_hosts", []) or []
    if top_hosts:
        lines.append("### Топ Hosts")
        lines.append("")
        lines.append("| Count | Host |")
        lines.append("|---|---|")
        for h in top_hosts[:10]:
            lines.append(f"| {h.get('count', 0)} | `{h.get('host', '?')}` |")
        lines.append("")

    # top URIs
    top_uris = http.get("top_uris", []) or []
    if top_uris:
        lines.append("### Топ URIs")
        lines.append("")
        lines.append("| Method | Host | URI | Src → Dst | UA | Bytes |")
        lines.append("|---|---|---|---|---|---|")
        for u in top_uris[:15]:
            method = u.get("method") or "?"
            host = u.get("host") or "?"
            uri = u.get("uri") or "?"
            src = f"{u.get('src_ip', '?')}:?"
            dst = f"{u.get('dst_ip', '?')}:{u.get('dst_port') or '-'}"
            ua = _short(u.get("user_agent") or "", 40)
            b = _fmt_bytes(u.get("bytes", 0))
            lines.append(
                f"| `{method}` | `{host}` | `{uri}` | `{src}` → `{dst}` | {ua} | {b} |"
            )
        lines.append("")

    # top user agents
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