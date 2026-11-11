"""Экспорт выдержки payload'а в Markdown-заметку кейса.

Перед выгрузкой вырезаются секреты, которые часто попадают в тела:
пароли, токены, API-ключи и заголовки Authorization. Сам payload
остаётся в fence-блоке, чтобы его можно было приложить к тикету,
не исполняя и не публикуя учётные данные.
"""
from __future__ import annotations

import re

from paradox.payload_analysis import PayloadAnalysis

_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\b"
    r"\s*[=:]\s*[\"']?([^\s\"',;]{4,})"
)
_AUTH_RE = re.compile(
    r"(?i)\bauthorization\b\s*[=:]\s*[^\r\n]{4,}",
)
_BEARER_RE = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{8,}=*",
)
_REDACTED = "<redacted>"


def redact_secrets(text: str) -> str:
    text = _AUTH_RE.sub(f"Authorization={_REDACTED}", text)
    text = _BEARER_RE.sub(f"Bearer {_REDACTED}", text)
    return _SECRET_RE.sub(
        lambda match: f"{match.group(1)}={_REDACTED}", text,
    )


def _fence(text: str) -> str:
    ticks = "````" if "```" in text else "```"
    return f"{ticks}text\n{text}\n{ticks}"


def _table(rows: list[tuple[str, str]]) -> str:
    lines = ["| Поле | Значение |", "|---|---|"]
    for key, value in rows:
        lines.append(f"| {key} | {value} |")
    return "\n".join(lines)


def build_markdown(
    *,
    data: bytes,
    analysis: PayloadAnalysis,
    meta: dict,
    variant_label: str = "",
    occurrences: list[dict] | None = None,
) -> str:
    """Markdown-заметка: метаданные, IOC, вложения, выдержка."""
    title = meta.get("finding_type") or "payload"
    value = meta.get("finding_value") or ""
    text = data.decode("utf-8", "replace")

    rows = [
        ("Finding", f"{title} — {value}"),
        ("Направление", str(meta.get("direction", ""))),
        ("Метод", str(meta.get("method", ""))),
        ("Цель", f"{meta.get('host', '')}{meta.get('uri', '')}"),
        ("Content-Type", str(meta.get("content_type", ""))),
        ("Размер", f"{analysis.size} байт"),
        ("Тип", f"{analysis.file_kind} · {analysis.mime}"),
        ("SHA256", analysis.sha256),
        ("MD5", analysis.md5),
        ("Энтропия", f"{analysis.entropy:.3f} bits/byte"),
    ]
    if variant_label:
        rows.append(("Представление", variant_label))
    if meta.get("truncated"):
        rows.append(("Выдержка", "тело обрезано лимитом выдержки"))

    sections = [
        f"# Payload: {title}",
        _table(rows),
    ]

    if analysis.urls or analysis.domains or analysis.ips or analysis.emails:
        iocs = []
        for label, values in (
            ("URL", analysis.urls),
            ("Домен", analysis.domains),
            ("IP", analysis.ips),
            ("E-mail", analysis.emails),
        ):
            for item in values[:20]:
                iocs.append(f"- {label}: `{item}`")
        sections.append("## IOC\n\n" + "\n".join(iocs))

    if analysis.embedded:
        embedded = []
        for item in analysis.embedded:
            size = f", {item.size} байт" if item.size else ""
            embedded.append(
                f"- {item.kind} @ 0x{item.offset:08x}{size}",
            )
        sections.append("## Вложенные файлы\n\n" + "\n".join(embedded))

    if analysis.strings:
        sections.append(
            "## Строки\n\n"
            + _fence("\n".join(analysis.strings[:40])),
        )

    if occurrences:
        repeats = [
            f"- {item.get('type', '?')} — {item.get('value', '')}"
            for item in occurrences[:20]
        ]
        sections.append("## Тот же payload\n\n" + "\n".join(repeats))

    excerpt = text if analysis.is_text else data[:4096].hex()
    sections.append(
        "## Выдержка\n\n" + _fence(redact_secrets(excerpt)),
    )
    return redact_secrets("\n\n".join(sections)) + "\n"
