"""Markdown-отчёт: document."""
from __future__ import annotations

from paradox.i18n import L
from paradox.reporters.markdown.format import (
    _fmt_bytes,
    _fmt_duration,
    _short,
)
from paradox.reporters.markdown.interpretation import (
    _render_interpretation,
)
from paradox.reporters.markdown.iocs import (
    _extract_iocs,
)
from paradox.reporters.markdown.sections import (
    _render_absence,
    _render_carved_files,
    _render_certificates,
    _render_contradictions,
    _render_entities,
    _render_findings,
    _render_http,
    _render_ndp,
)
from paradox.reporters.markdown.timeline import (
    _render_timeline,
)
from paradox.reporters.markdown.tldr import (
    _render_tldr,
)


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

    lines.append(
        f"**{L('Инструмент:', 'Tool:')}** "
        f"Paradox v{provenance.get('tool_version', '?')}  "
    )
    lines.append(f"**{L('Файл:', 'File:')}** `{pcap_path}`  ")
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
    lines.append(L("## Сводка", "## Summary"))
    lines.append("")
    lines.append(
        f"- **{L('Пакеты:', 'Packets:')}** {summary.get('packets', 0):,}"
    )
    lines.append(f"- **Flows:** {summary.get('flows', 0):,}")
    lines.append(
        f"- **{L('Уникальных DNS-запросов:', 'Unique DNS queries:')}** "
        f"{summary.get('unique_dns_queries', 0)}"
    )
    lines.append(f"- **NXDOMAIN:** {summary.get('nxdomain_count', 0)}")
    lines.append(f"- **Findings:** {summary.get('findings', 0)}")
    if contradictions:
        lines.append(
            f"- **{L('Противоречий:', 'Contradictions:')}** "
            f"{len(contradictions)}"
        )

    first_ts = summary.get("first_ts")
    last_ts = summary.get("last_ts")
    if first_ts and last_ts:
        duration = last_ts - first_ts
        lines.append(
            f"- **{L('Период:', 'Period:')}** {_fmt_duration(duration)}"
        )

    uploaded = summary.get("uploaded_bytes")
    downloaded = summary.get("downloaded_bytes")
    if uploaded is not None and downloaded is not None:
        lines.append(f"- **Uploaded (internal → external):** {_fmt_bytes(uploaded)}")
        lines.append(f"- **Downloaded (external → internal):** {_fmt_bytes(downloaded)}")

    protocols = summary.get("protocols") or {}
    by_l4 = protocols.get("by_l4") or {}
    by_l7 = protocols.get("by_l7") or {}
    if by_l4:
        lines.append(
            "- **L4 (flows):** "
            + ", ".join(f"{k}: {v}" for k, v in by_l4.items())
        )
    if by_l7:
        lines.append(
            "- **L7 (flows):** "
            + ", ".join(f"{k}: {v}" for k, v in by_l7.items())
        )

    extractor_errors = summary.get("extractor_errors") or {}
    if extractor_errors:
        lines.append(
            f"- **{L('Ошибки экстракторов:', 'Extractor errors:')}** "
            f"`{extractor_errors}`"
        )
    truncated_streams = summary.get("tcp_streams_truncated", 0)
    if truncated_streams:
        lines.append(
            f"- **⚠️ {L('Обрезано TCP-потоков:', 'Truncated TCP streams:')}** "
            f"{truncated_streams}. "
            + L(
                "HTTP-объекты, веб-шеллы и YARA могли не увидеть часть трафика.",
                "HTTP objects, webshells and YARA may have missed part of the traffic.",
            )
        )
    lines.append("")

    # --- entities ---
    if entities:
        lines.extend(_render_entities(entities, findings))
        lines.append("")

    # --- NDP ---
    lines.extend(_render_ndp(report))

    # --- Certificates ---
    lines.extend(_render_certificates(report))

    # --- findings ---
    lines.extend(_render_findings(findings))

    # --- contradictions ---
    contradictions_section = _render_contradictions(report)
    if contradictions_section:
        lines.extend(contradictions_section)
        lines.append("")

    # --- interpretation ---
    lines.extend(_render_interpretation(report))

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
            lines.append(f"**{L('Домены:', 'Domains:')}**")
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
            lines.append(f"**{L('Порты:', 'Ports:')}**")
            lines.append("")
            for port, reasons in sorted(iocs["ports"].items()):
                lines.append(f"- `{port}` — {', '.join(reasons)}")
            lines.append("")

    # --- top flows ---
    if top_flows:
        lines.append(
            L("## Топ-10 flows по байтам", "## Top 10 flows by bytes")
        )
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
    lines.append(
        L(
            "_Отчёт сгенерирован автоматически. Проверяй findings глазами: "
            "эвристики дают кандидатов, не приговоры._",
            "_Report generated automatically. Review findings by hand: "
            "heuristics produce candidates, not verdicts._",
        )
    )
    lines.append("")
    lines.append("***")
    lines.append("")
    lines.append("**Paradox** v" + provenance.get("tool_version", "?") +
                 " · © 2026 Andrey Grigoryev (v314xm)")
    lines.append("")

    return "\n".join(lines)
