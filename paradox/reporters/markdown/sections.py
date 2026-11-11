"""Markdown-отчёт: sections."""
from __future__ import annotations

from paradox.reporters.markdown.format import (
    _escape_cell,
    _fmt_bytes,
    _fmt_host,
    _short,
)
from paradox.reporters.markdown.mitre import (
    _mitre_for_finding,
)


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


def _render_findings(findings: list[dict]) -> list[str]:
    lines: list[str] = []
    if not findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("_Ничего не найдено._")
        lines.append("")
        return lines

    lines.append(f"## Findings ({len(findings)})")
    lines.append("")
    lines.append("| Тип | Значение | Conf | MITRE |")
    lines.append("|---|---|---|---|")
    for f in findings[:50]:
        ftype = _escape_cell(str(f.get("type", "?")))
        value = _escape_cell(_short(str(f.get("value", "")), 60))
        conf = f.get("confidence")
        conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else "—"
        mitre = _escape_cell(_mitre_for_finding(f))
        lines.append(f"| `{ftype}` | {value} | {conf_str} | {mitre} |")
    if len(findings) > 50:
        lines.append(f"| ... | _(ещё {len(findings) - 50})_ | | |")
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


def _render_certificates(report: dict) -> list[str]:
    certs = report.get("certificates") or {}
    total = certs.get("total", 0)
    parse_errors = certs.get("parse_errors", 0)
    items = certs.get("items") or []

    if not total and not parse_errors:
        return []

    lines = [f"## X.509 сертификаты ({total})", ""]

    if items:
        lines.append("| Сервер | CN | Issuer | Действует до | Self-signed |")
        lines.append("|---|---|---|---|---|")
        for c in items:
            port = c.get("dst_port")
            port_text = port if port is not None else "?"
            server = f"`{c.get('dst_ip', '?')}:{port_text}`"
            lines.append(
                f"| {server} | {_escape_cell(c.get('subject_cn') or '—')} "
                f"| {_escape_cell(c.get('issuer_cn') or '—')} "
                f"| {c.get('not_after') or '?'} "
                f"| {'да' if c.get('self_signed') else '—'} |"
            )
        lines.append("")

    if certs.get("truncated"):
        lines.append("Показаны не все сертификаты (лимит top-N).")
        lines.append("")

    if parse_errors:
        lines.append(f"⚠️ Не удалось разобрать DER-сертификатов: {parse_errors}.")
        lines.append("")

    return lines
