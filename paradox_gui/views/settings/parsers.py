"""Парсинг и форматирование списков портов/строк для настроек."""
from __future__ import annotations


def _parse_ports(text: str) -> frozenset[int]:
    """'80, 443 8080 # web' → {80, 443, 8080}.

    Разделители — пробелы, запятые, переводы строк. Комментарии (после #)
    игнорируются. Невалидные токены пропускаются молча: GUI не должен
    падать из-за опечатки.
    """
    out: set[int] = set()
    for chunk in text.replace(",", " ").split():
        if chunk.startswith("#"):
            break
        try:
            p = int(chunk)
        except ValueError:
            continue
        if 1 <= p <= 65535:
            out.add(p)
    return frozenset(out)


def _parse_ports_with_report(text: str) -> tuple[frozenset[int], list[str]]:
    """Как _parse_ports, но возвращает список пропущенных токенов.

    Используется в _apply_* для счётчика «N пропущено».
    """
    out: set[int] = set()
    skipped: list[str] = []
    for chunk in text.replace(",", " ").split():
        if chunk.startswith("#"):
            break
        try:
            p = int(chunk)
        except ValueError:
            skipped.append(chunk)
            continue
        if 1 <= p <= 65535:
            out.add(p)
        else:
            skipped.append(chunk)
    return frozenset(out), skipped


def _format_ports(ports) -> str:
    """{443, 80} → '80, 443'. Сортировка — стабильный порядок в UI."""
    return ", ".join(str(p) for p in sorted(ports))


def _parse_lines(text: str) -> frozenset[str]:
    """Один элемент на строку. Пустые строки и # комментарии — пропуск."""
    return frozenset(
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def _format_lines(items) -> str:
    """frozenset[str] → многострочный текст, сортировка для стабильности."""
    return "\n".join(sorted(items))


def _is_port_key(key: str) -> bool:
    if key in _PORT_TEXT_KEYS:
        return True
    return "ports" in key


_PORT_TEXT_KEYS = {
    "suspicious_ports",
    "port_scan_excluded_ports",
    "dc_service_ports",
    "lateral_movement_ports",
    "beaconing_mail_polling_ports",
    "brute_force_skip_tls_ports",
}
