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


def _extract_iocs(findings: list[dict]) -> dict:
    """Простое извлечение IOC из findings.

    Пока без секции entities — только то, что явно в findings.
    """
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
            # value = "ip:port"
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

    uploaded = summary.get("uploaded_bytes", 0)
    downloaded = summary.get("downloaded_bytes", 0)
    if uploaded or downloaded:
        lines.append(f"- **Uploaded (internal → external):** {_fmt_bytes(uploaded)}")
        lines.append(f"- **Downloaded (external → internal):** {_fmt_bytes(downloaded)}")

    first_ts = summary.get("first_ts")
    last_ts = summary.get("last_ts")
    if first_ts and last_ts:
        duration = last_ts - first_ts
        lines.append(f"- **Период:** {_fmt_duration(duration)}")

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
    # --- top flows ---
    if top_flows:
        lines.append("## Топ-10 flows по байтам")
        lines.append("")
        lines.append("| Src | Dst | Dir | Proto | Bytes | SNI |")
        lines.append("|---|---|---|---|---|---|")
        for fl in top_flows[:10]:
            src = f"{fl.get('src_ip', '?')}:{fl.get('src_port') or '-'}"
            dst = f"{fl.get('dst_ip', '?')}:{fl.get('dst_port') or '-'}"
            direction = fl.get("direction", "?")
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

    # --- internal ---
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

            sni = e.get("sni_domains", [])
            if sni:
                shown = ", ".join(f"`{d}`" for d in sni[:5])
                more = f" _(+{len(sni) - 5})_" if len(sni) > 5 else ""
                lines.append(f"  SNI: {shown}{more}  ")

            dns = e.get("dns_names", [])
            if dns:
                shown = ", ".join(f"`{d}`" for d in dns[:5])
                more = f" _(+{len(dns) - 5})_" if len(dns) > 5 else ""
                lines.append(f"  DNS: {shown}{more}  ")

            fnd = e.get("findings_indices", [])
            if fnd:
                lines.append(f"  Findings: #{', #'.join(str(x) for x in fnd)}  ")

            lines.append("")

    # --- external с findings ---
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

            sni = e.get("sni_domains", [])
            if sni:
                shown = ", ".join(f"`{d}`" for d in sni[:5])
                lines.append(f"  SNI: {shown}  ")

            fnd = e.get("findings_indices", [])
            lines.append(f"  Findings: #{', #'.join(str(x) for x in fnd)}  ")

            lines.append("")

    # --- external без findings — только топ-5 ---
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