"""
Самодостаточный HTML-отчёт по результатам прогона.

Зачем: у Markdown-отчёта нет таблиц и цветовых акцентов, а PDF
требует внешних библиотек. HTML-файл со встроенным CSS открывается
в любом браузере и печатается в PDF через «Печать → Сохранить как
PDF» — без зависимостей и без сети.

Что внутри:
  - сводка (пакеты, flows, findings, противоречия, протоколы);
  - findings, отсортированные по severity и confidence;
  - противоречия с фактами и подсказкой по разбору;
  - таймлайн kill-chain;
  - IOC (внешние IP и домены) из findings.

Безопасность: все значения экранируются (html.escape), evidence
показывается как JSON в <pre> с обрезкой — отчёт можно открывать,
не опасаясь HTML из захваченного трафика.
"""
import html
import json
from datetime import UTC, datetime
from pathlib import Path

from paradox.reporters.stix_reporter import extract_iocs

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_EVIDENCE_LIMIT = 4000

_STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
    margin: 0; padding: 32px;
    font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    background: #f6f7f9; color: #1c2430;
}
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 12px; }
.muted { color: #5b6878; }
.mono { font-family: "Cascadia Mono", Consolas, monospace; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.card {
    background: #fff; border: 1px solid #dde2e8; border-radius: 8px;
    padding: 12px 14px;
}
.card .v { font-size: 22px; font-weight: 600; }
.card .l { font-size: 12px; color: #5b6878; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #dde2e8; border-radius: 8px; overflow: hidden; }
th, td { padding: 8px 10px; text-align: left; vertical-align: top;
         border-bottom: 1px solid #eef1f4; }
th { background: #f0f3f6; font-size: 12px; text-transform: uppercase;
     letter-spacing: .03em; color: #465364; }
tr:last-child td { border-bottom: none; }
.sev { display: inline-block; padding: 1px 8px; border-radius: 10px;
       font-size: 11px; font-weight: 700; text-transform: uppercase; }
.sev-critical { background: #ffe1e1; color: #a11b1b; }
.sev-high     { background: #ffe9d6; color: #9a4b00; }
.sev-medium   { background: #fff4cc; color: #7a5d00; }
.sev-low      { background: #e3f0ff; color: #1d4f8c; }
.sev-info     { background: #e9edf2; color: #3d4b5c; }
details { margin-top: 4px; }
details pre {
    background: #10161f; color: #d9e2ec; padding: 10px;
    border-radius: 6px; overflow-x: auto; font-size: 12px;
    white-space: pre-wrap; word-break: break-word;
}
.contradiction { background: #fff; border: 1px solid #dde2e8;
                 border-left: 4px solid #a11b1b; border-radius: 8px;
                 padding: 14px 16px; margin-bottom: 12px; }
.contradiction .rule { font-weight: 700; }
.contradiction ul { margin: 6px 0 0 18px; padding: 0; }
.timeline { background: #fff; border: 1px solid #dde2e8;
            border-radius: 8px; padding: 4px 16px; }
.timeline li { margin: 10px 0; }
.ioc { display: flex; flex-wrap: wrap; gap: 8px; }
.ioc code { background: #fff; border: 1px solid #dde2e8;
            border-radius: 6px; padding: 3px 8px; }
footer { margin-top: 40px; color: #6b7787; font-size: 12px; }
@media print {
    body { background: #fff; padding: 0; }
    .card, table, .contradiction, .timeline { break-inside: avoid; }
    details { display: none; }
}
""".strip()


def _esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _fmt_ts(ts) -> str:
    if ts is None:
        return ""
    try:
        moment = datetime.fromtimestamp(float(ts), tz=UTC)
    except (ValueError, OSError, OverflowError):
        return ""
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_bytes(value) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if number < 1024 or unit == "TB":
            return f"{number:.0f} {unit}" if unit == "B" else f"{number:.1f} {unit}"
        number /= 1024
    return ""


def _sev(value: str) -> str:
    severity = str(value or "info").lower()
    if severity not in _SEVERITY_ORDER:
        severity = "info"
    return (
        f'<span class="sev sev-{severity}">{_esc(severity)}</span>'
    )


def _summary_cards(summary: dict) -> str:
    cards = [
        ("Пакетов", summary.get("packets", 0)),
        ("Flows", summary.get("flows", 0)),
        ("HTTP-объектов", summary.get("http_objects", 0)),
        ("Findings", summary.get("findings", 0)),
        ("Противоречий", summary.get("contradictions", 0)),
        ("Уникальных DNS", summary.get("unique_dns_queries", 0)),
        ("Carved файлов", summary.get("carved_files", 0)),
        ("Отправлено", _fmt_bytes(summary.get("uploaded_bytes"))),
    ]
    return '<div class="cards">' + "".join(
        f'<div class="card"><div class="v">{_esc(value)}</div>'
        f'<div class="l">{_esc(label)}</div></div>'
        for label, value in cards
    ) + "</div>"


def _protocols(summary: dict) -> str:
    protocols = summary.get("protocols") or {}
    parts = []
    for layer in ("by_l4", "by_l7"):
        values = protocols.get(layer) or {}
        if values:
            body = ", ".join(
                f"{_esc(name)}: {_esc(count)}"
                for name, count in values.items()
            )
            parts.append(f"<b>{_esc(layer)}</b> — {body}")
    if not parts:
        return ""
    return (
        '<p class="muted">Протоколы: ' + " · ".join(parts) + "</p>"
    )


def _evidence(finding: dict) -> str:
    evidence = finding.get("evidence") or {}
    if not evidence:
        return ""
    try:
        text = json.dumps(evidence, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        text = str(evidence)
    if len(text) > _EVIDENCE_LIMIT:
        text = text[:_EVIDENCE_LIMIT] + "\n… (обрезано)"
    return (
        "<details><summary>evidence</summary>"
        f"<pre>{_esc(text)}</pre></details>"
    )


def _findings_section(findings: list) -> str:
    if not findings:
        return '<p class="muted">Findings не найдены.</p>'

    ordered = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "info")), 9),
            -float(f.get("confidence") or 0),
            str(f.get("type", "")),
        ),
    )
    rows = []
    for f in ordered:
        src = f.get("src_ip") or ""
        dst = f.get("dst_ip") or ""
        if f.get("dst_port") is not None:
            dst = f"{dst}:{f['dst_port']}" if dst else str(f["dst_port"])
        rows.append(
            "<tr>"
            f"<td>{_sev(f.get('severity'))}</td>"
            f"<td class='mono'>{_esc(f.get('type'))}</td>"
            f"<td>{_esc(f.get('value'))}{_evidence(f)}</td>"
            f"<td>{_esc(f.get('confidence'))}</td>"
            f"<td class='mono'>{_esc(f.get('mitre_id'))}</td>"
            f"<td class='mono'>{_esc(src)} → {_esc(dst)}</td>"
            f"<td class='mono'>{_esc(_fmt_ts(f.get('first_seen')))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>Severity</th><th>Тип</th><th>Что найдено</th>"
        "<th>Conf</th><th>MITRE</th><th>Откуда → Куда</th><th>Первое</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _contradictions_section(items: list) -> str:
    if not items:
        return '<p class="muted">Противоречий не найдено.</p>'
    blocks = []
    ordered = sorted(
        items,
        key=lambda c: (
            _SEVERITY_ORDER.get(str(c.get("severity", "info")), 9),
            -float(c.get("priority") or 0),
        ),
    )
    for item in ordered:
        facts = "".join(
            "<li><span class='mono'>"
            f"{_esc(fact.get('source'))}: {_esc(fact.get('subject'))} "
            f"{_esc(fact.get('predicate'))} = {_esc(fact.get('value'))}"
            "</span></li>"
            for fact in (item.get("facts") or [])
        )
        causes = item.get("likely_causes") or []
        causes_html = ""
        if causes:
            causes_html = "<p class='muted'>Вероятные причины: " + _esc(
                "; ".join(str(c) for c in causes)
            ) + "</p>"
        hint = item.get("resolution_hint")
        hint_html = (
            f"<p class='muted'>Как разбирать: {_esc(hint)}</p>"
            if hint else ""
        )
        blocks.append(
            '<div class="contradiction">'
            f"<div class='rule'>{_esc(item.get('rule'))} "
            f"{_sev(item.get('severity'))}</div>"
            f"<div>Субъект: <span class='mono'>{_esc(item.get('subject'))}</span>"
            f" · confidence {_esc(item.get('confidence'))}</div>"
            f"{causes_html}{hint_html}"
            f"<ul>{facts}</ul></div>"
        )
    return "".join(blocks)


def _timeline_section(events: list) -> str:
    if not events:
        return '<p class="muted">Таймлайн пуст.</p>'
    rows = "".join(
        "<li>"
        f"{_esc(_fmt_ts(event.get('ts')))} · "
        f"<b>{_esc(event.get('phase'))}</b> · "
        f"{_sev(event.get('severity'))} "
        f"<span class='mono'>{_esc(event.get('type'))}</span> — "
        f"{_esc(event.get('description'))}"
        "</li>"
        for event in events
    )
    return f'<ul class="timeline">{rows}</ul>'


def _ioc_section(findings: list) -> str:
    indicators = extract_iocs(findings)
    if not indicators:
        return '<p class="muted">IOC не найдены.</p>'
    chips = "".join(
        f"<code>{_esc(ind['pattern'])}</code>" for ind in indicators
    )
    return f'<div class="ioc">{chips}</div>'


def render_html(report: dict) -> str:
    """Собрать полный HTML-документ отчёта."""
    provenance = report.get("provenance") or {}
    summary = report.get("summary") or {}
    findings = report.get("findings") or []
    contradictions = report.get("contradictions") or []
    timeline = report.get("timeline") or []

    pcap = provenance.get("pcap_path") or "pcap"
    title = f"Paradox — отчёт: {pcap}"

    meta = []
    for label, key in (
        ("Инструмент", "tool_version"),
        ("Файл", "pcap_path"),
        ("SHA256", "pcap_sha256"),
    ):
        value = provenance.get(key)
        if value:
            meta.append(
                f"<li>{_esc(label)}: <span class='mono'>{_esc(value)}</span></li>"
            )

    return (
        "<!doctype html>\n"
        '<html lang="ru">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>{_STYLE}</style>\n</head>\n<body>\n<main>\n"
        f"<h1>{_esc(title)}</h1>\n"
        f"<ul class='muted'>{''.join(meta)}</ul>\n"
        f"<h2>Сводка</h2>\n{_summary_cards(summary)}\n"
        f"{_protocols(summary)}\n"
        f"<h2>Findings ({len(findings)})</h2>\n"
        f"{_findings_section(findings)}\n"
        f"<h2>Противоречия ({len(contradictions)})</h2>\n"
        f"{_contradictions_section(contradictions)}\n"
        f"<h2>Таймлайн</h2>\n{_timeline_section(timeline)}\n"
        f"<h2>IOC</h2>\n{_ioc_section(findings)}\n"
        "<footer>Отчёт сгенерирован Paradox. "
        "Для PDF: Печать → Сохранить как PDF.</footer>\n"
        "</main>\n</body>\n</html>\n"
    )


def write_html(report: dict, path: Path) -> Path:
    path = Path(path)
    path.write_text(render_html(report), encoding="utf-8")
    return path
