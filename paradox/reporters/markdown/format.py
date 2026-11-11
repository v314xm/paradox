"""Markdown-отчёт: format."""
from __future__ import annotations

from ipaddress import ip_address


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
    seconds = max(seconds, 0)
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


def _escape_cell(s: str) -> str:
    """Экранировать | для markdown-таблицы."""
    return (s or "").replace("|", "\\|")
